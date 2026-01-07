"""SAML service layer.

This module provides business logic for SAML SSO operations:
- IdP management (CRUD)
- SP certificate management
- SAML request/response processing
- Metadata import and refresh

All functions follow the service layer pattern:
- Receive RequestingUser for authorization (except public auth endpoints)
- Return Pydantic schemas
- Raise ServiceError subclasses on failure
- Log events for all writes
"""

import logging
from typing import Any

import database
from schemas.saml import (
    AuthRouteResult,
    DomainBinding,
    DomainBindingList,
    IdPConfig,
    IdPCreate,
    IdPForLogin,
    IdPListItem,
    IdPListResponse,
    IdPMetadataParsed,
    IdPUpdate,
    MetadataRefreshResult,
    MetadataRefreshSummary,
    SAMLAttributes,
    SAMLAuthResult,
    SAMLTestResult,
    SPCertificate,
    SPMetadata,
    UnboundDomain,
)
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser
from utils.saml import (
    decrypt_private_key,
    encrypt_private_key,
    fetch_idp_metadata,
    generate_sp_certificate,
    generate_sp_metadata_xml,
    get_certificate_expiry,
    parse_idp_metadata_xml,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Authorization Helpers
# ============================================================================


def _require_super_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not super_admin."""
    if user["role"] != "super_admin":
        raise ForbiddenError(
            message="Super admin access required",
            code="super_admin_required",
            required_role="super_admin",
        )


# ============================================================================
# SP Certificate Operations
# ============================================================================


def get_or_create_sp_certificate(
    requesting_user: RequestingUser,
) -> SPCertificate:
    """
    Get existing SP certificate or generate a new one.

    Authorization: Requires super_admin role.

    If no certificate exists for the tenant, generates a self-signed
    certificate valid for 10 years.

    Returns:
        SPCertificate with certificate_pem (no private key exposed)
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Try to get existing certificate
    cert = database.saml.get_sp_certificate(tenant_id)

    if cert:
        return SPCertificate(
            id=str(cert["id"]),
            certificate_pem=cert["certificate_pem"],
            expires_at=cert["expires_at"],
            created_at=cert["created_at"],
        )

    # Generate new certificate
    cert_pem, key_pem = generate_sp_certificate(tenant_id)
    encrypted_key = encrypt_private_key(key_pem)
    expires_at = get_certificate_expiry(cert_pem)

    cert = database.saml.create_sp_certificate(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=requesting_user["id"],
    )

    if cert is None:
        raise ValidationError(
            message="Failed to create SP certificate",
            code="sp_certificate_creation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_sp_certificate",
        artifact_id=str(cert["id"]),
        event_type="saml_sp_certificate_created",
        metadata={"expires_at": str(expires_at)},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return SPCertificate(
        id=str(cert["id"]),
        certificate_pem=cert["certificate_pem"],
        expires_at=cert["expires_at"],
        created_at=cert["created_at"],
    )


def get_sp_metadata(
    requesting_user: RequestingUser,
    base_url: str,
) -> SPMetadata:
    """
    Get SP metadata info for display in admin UI.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user
        base_url: Base URL for generating metadata URL

    Returns:
        SPMetadata with entity_id, acs_url, metadata_url, certificate info
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Get or create certificate
    cert = get_or_create_sp_certificate(requesting_user)

    # Generate metadata URL
    metadata_url = f"{base_url}/saml/metadata"
    acs_url = f"{base_url}/saml/acs"  # Generic ACS URL

    return SPMetadata(
        entity_id=metadata_url,
        acs_url=acs_url,
        metadata_url=metadata_url,
        certificate_pem=cert.certificate_pem,
        certificate_expires_at=cert.expires_at,
    )


def get_tenant_sp_metadata_xml(tenant_id: str, base_url: str) -> str:
    """
    Generate SP metadata XML for IdPs to consume.

    No authorization required (public endpoint).

    Args:
        tenant_id: Tenant ID
        base_url: Base URL for the tenant

    Returns:
        XML metadata string
    """
    cert = database.saml.get_sp_certificate(tenant_id)

    if cert is None:
        raise NotFoundError(
            message="SP certificate not configured",
            code="sp_certificate_not_found",
        )

    entity_id = f"{base_url}/saml/metadata"
    acs_url = f"{base_url}/saml/acs"

    return generate_sp_metadata_xml(
        entity_id=entity_id,
        acs_url=acs_url,
        certificate_pem=cert["certificate_pem"],
    )


# ============================================================================
# IdP CRUD Operations
# ============================================================================


def _idp_row_to_config(row: dict) -> IdPConfig:
    """Convert database row to IdPConfig schema."""
    # Compute sp_acs_url from sp_entity_id (shared ACS URL for all IdPs)
    sp_entity_id = row["sp_entity_id"]
    sp_acs_url = sp_entity_id.replace("/saml/metadata", "/saml/acs")

    return IdPConfig(
        id=str(row["id"]),
        name=row["name"],
        provider_type=row["provider_type"],
        entity_id=row["entity_id"],
        sso_url=row["sso_url"],
        slo_url=row["slo_url"],
        certificate_pem=row["certificate_pem"],
        metadata_url=row["metadata_url"],
        metadata_last_fetched_at=row["metadata_last_fetched_at"],
        metadata_fetch_error=row["metadata_fetch_error"],
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_acs_url,
        attribute_mapping=row["attribute_mapping"],
        is_enabled=row["is_enabled"],
        is_default=row["is_default"],
        require_platform_mfa=row["require_platform_mfa"],
        jit_provisioning=row["jit_provisioning"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _idp_row_to_list_item(row: dict) -> IdPListItem:
    """Convert database row to IdPListItem schema."""
    return IdPListItem(
        id=str(row["id"]),
        name=row["name"],
        provider_type=row["provider_type"],
        is_enabled=row["is_enabled"],
        is_default=row["is_default"],
        metadata_url=row["metadata_url"],
        metadata_last_fetched_at=row["metadata_last_fetched_at"],
        metadata_fetch_error=row["metadata_fetch_error"],
        created_at=row["created_at"],
    )


def list_identity_providers(
    requesting_user: RequestingUser,
) -> IdPListResponse:
    """
    List all IdPs for the tenant.

    Authorization: Requires super_admin role.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.saml.list_identity_providers(requesting_user["tenant_id"])
    items = [_idp_row_to_list_item(row) for row in rows]

    return IdPListResponse(items=items, total=len(items))


def get_identity_provider(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Get a single IdP configuration.

    Authorization: Requires super_admin role.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    row = database.saml.get_identity_provider(requesting_user["tenant_id"], idp_id)

    if row is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    return _idp_row_to_config(row)


def create_identity_provider(
    requesting_user: RequestingUser,
    data: IdPCreate,
    base_url: str,
) -> IdPConfig:
    """
    Create a new IdP configuration.

    Authorization: Requires super_admin role.

    Also ensures SP certificate exists for the tenant.
    Logs: saml_idp_created event.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Ensure SP certificate exists
    get_or_create_sp_certificate(requesting_user)

    # Check for duplicate entity_id
    existing = database.saml.get_identity_provider_by_entity_id(tenant_id, data.entity_id)
    if existing:
        raise ConflictError(
            message=f"An IdP with entity ID '{data.entity_id}' already exists",
            code="idp_entity_id_exists",
        )

    # Generate SP entity ID (ACS URL is derived from this: /saml/metadata -> /saml/acs)
    sp_entity_id = f"{base_url}/saml/metadata"

    row = database.saml.create_identity_provider(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=data.name,
        provider_type=data.provider_type,
        entity_id=data.entity_id,
        sso_url=data.sso_url,
        slo_url=data.slo_url,
        certificate_pem=data.certificate_pem,
        metadata_url=data.metadata_url,
        sp_entity_id=sp_entity_id,
        attribute_mapping=data.attribute_mapping,
        is_enabled=data.is_enabled,
        is_default=data.is_default,
        require_platform_mfa=data.require_platform_mfa,
        jit_provisioning=data.jit_provisioning,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to create identity provider",
            code="idp_creation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=str(row["id"]),
        event_type="saml_idp_created",
        metadata={
            "name": data.name,
            "provider_type": data.provider_type,
            "entity_id": data.entity_id,
            "is_enabled": data.is_enabled,
        },
        request_metadata=requesting_user.get("request_metadata"),
    )

    return _idp_row_to_config(row)


def update_identity_provider(
    requesting_user: RequestingUser,
    idp_id: str,
    data: IdPUpdate,
) -> IdPConfig:
    """
    Update an existing IdP configuration.

    Authorization: Requires super_admin role.
    Logs: saml_idp_updated event.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Build update kwargs from non-None fields
    update_kwargs: dict[str, Any] = {}
    for field in [
        "name",
        "sso_url",
        "slo_url",
        "certificate_pem",
        "metadata_url",
        "attribute_mapping",
        "require_platform_mfa",
        "jit_provisioning",
    ]:
        value = getattr(data, field, None)
        if value is not None:
            update_kwargs[field] = value

    if not update_kwargs:
        return _idp_row_to_config(existing)

    row = database.saml.update_identity_provider(tenant_id, idp_id, **update_kwargs)

    if row is None:
        raise ValidationError(
            message="Failed to update identity provider",
            code="idp_update_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_updated",
        metadata={"updated_fields": list(update_kwargs.keys())},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return _idp_row_to_config(row)


def delete_identity_provider(
    requesting_user: RequestingUser,
    idp_id: str,
) -> None:
    """
    Delete an IdP configuration.

    Authorization: Requires super_admin role.
    Logs: saml_idp_deleted event.

    Security: Cannot delete if users are assigned or domains are bound.
    Must explicitly migrate users/unbind domains first.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists and get name for event log
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Security check: Block if users are assigned to this IdP
    user_count = database.saml.count_users_with_idp(tenant_id, idp_id)
    if user_count > 0:
        raise ConflictError(
            message=f"Cannot delete IdP: {user_count} user(s) are assigned to it. "
            "Migrate users to another IdP or set them to 'password only' first.",
            code="idp_has_assigned_users",
            details={"user_count": user_count, "idp_id": idp_id},
        )

    # Security check: Block if domains are bound to this IdP
    domain_count = database.saml.count_domain_bindings_for_idp(tenant_id, idp_id)
    if domain_count > 0:
        raise ConflictError(
            message=f"Cannot delete IdP: {domain_count} domain(s) are bound to it. "
            "Unbind or rebind domains first.",
            code="idp_has_bound_domains",
            details={"domain_count": domain_count, "idp_id": idp_id},
        )

    database.saml.delete_identity_provider(tenant_id, idp_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_deleted",
        metadata={"name": existing["name"]},
        request_metadata=requesting_user.get("request_metadata"),
    )


def set_idp_enabled(
    requesting_user: RequestingUser,
    idp_id: str,
    enabled: bool,
) -> IdPConfig:
    """
    Enable or disable an IdP.

    Authorization: Requires super_admin role.
    Logs: saml_idp_enabled or saml_idp_disabled event.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    row = database.saml.set_idp_enabled(tenant_id, idp_id, enabled)

    if row is None:
        raise ValidationError(
            message="Failed to update identity provider",
            code="idp_update_failed",
        )

    event_type = "saml_idp_enabled" if enabled else "saml_idp_disabled"
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type=event_type,
        metadata={"name": existing["name"]},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return _idp_row_to_config(row)


def set_idp_default(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Set an IdP as the default for the tenant.

    Authorization: Requires super_admin role.
    Logs: saml_idp_set_default event.
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    row = database.saml.set_idp_default(tenant_id, idp_id)

    if row is None:
        raise ValidationError(
            message="Failed to update identity provider",
            code="idp_update_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_set_default",
        metadata={"name": existing["name"]},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return _idp_row_to_config(row)


# ============================================================================
# IdP Metadata Import & Refresh
# ============================================================================


def fetch_and_parse_idp_metadata(url: str) -> IdPMetadataParsed:
    """
    Fetch and parse IdP metadata from URL.

    No authorization required (used during import flow).

    Args:
        url: Metadata URL

    Returns:
        IdPMetadataParsed with entity_id, sso_url, slo_url, certificate_pem

    Raises:
        ValidationError if fetch fails or metadata is invalid
    """
    try:
        xml_content = fetch_idp_metadata(url)
        parsed = parse_idp_metadata_xml(xml_content)

        return IdPMetadataParsed(
            entity_id=parsed["entity_id"],
            sso_url=parsed["sso_url"],
            slo_url=parsed["slo_url"],
            certificate_pem=parsed["certificate_pem"],
        )
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="metadata_fetch_failed",
        ) from e


def import_idp_from_metadata_url(
    requesting_user: RequestingUser,
    name: str,
    provider_type: str,
    metadata_url: str,
    base_url: str,
) -> IdPConfig:
    """
    Import and create an IdP from metadata URL.

    Authorization: Requires super_admin role.

    Fetches metadata, parses it, and creates the IdP configuration.
    The metadata_url is stored for future auto-refresh.

    Returns:
        Created IdPConfig
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Fetch and parse metadata
    metadata = fetch_and_parse_idp_metadata(metadata_url)

    # Create IdP using parsed metadata
    data = IdPCreate(
        name=name,
        provider_type=provider_type,
        entity_id=metadata.entity_id,
        sso_url=metadata.sso_url,
        slo_url=metadata.slo_url,
        certificate_pem=metadata.certificate_pem,
        metadata_url=metadata_url,
        is_enabled=False,  # Start disabled, admin must enable
    )

    return create_identity_provider(requesting_user, data, base_url)


def parse_idp_metadata_xml_to_schema(metadata_xml: str) -> IdPMetadataParsed:
    """
    Parse raw IdP metadata XML directly.

    No authorization required (used during import flow).

    Args:
        metadata_xml: Raw SAML metadata XML content

    Returns:
        IdPMetadataParsed with entity_id, sso_url, slo_url, certificate_pem

    Raises:
        ValidationError if metadata is invalid
    """
    try:
        parsed = parse_idp_metadata_xml(metadata_xml)

        return IdPMetadataParsed(
            entity_id=parsed["entity_id"],
            sso_url=parsed["sso_url"],
            slo_url=parsed["slo_url"],
            certificate_pem=parsed["certificate_pem"],
        )
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="metadata_parse_failed",
        ) from e


def import_idp_from_metadata_xml(
    requesting_user: RequestingUser,
    name: str,
    provider_type: str,
    metadata_xml: str,
    base_url: str,
) -> IdPConfig:
    """
    Import and create an IdP from raw metadata XML.

    Authorization: Requires super_admin role.

    Parses the XML and creates the IdP configuration.
    No metadata_url is stored since this is a direct XML import.

    Returns:
        Created IdPConfig
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Parse metadata XML directly
    metadata = parse_idp_metadata_xml_to_schema(metadata_xml)

    # Create IdP using parsed metadata (no metadata_url since imported from XML)
    data = IdPCreate(
        name=name,
        provider_type=provider_type,
        entity_id=metadata.entity_id,
        sso_url=metadata.sso_url,
        slo_url=metadata.slo_url,
        certificate_pem=metadata.certificate_pem,
        metadata_url=None,  # No URL to store - imported from raw XML
        is_enabled=False,  # Start disabled, admin must enable
    )

    return create_identity_provider(requesting_user, data, base_url)


def refresh_idp_from_metadata(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Manually refresh an IdP from its metadata URL.

    Authorization: Requires super_admin role.

    Returns:
        Updated IdPConfig

    Raises:
        ValidationError if IdP has no metadata URL or refresh fails
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get current IdP
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    if not existing["metadata_url"]:
        raise ValidationError(
            message="Identity provider has no metadata URL configured",
            code="no_metadata_url",
        )

    # Fetch and parse metadata
    try:
        metadata = fetch_and_parse_idp_metadata(existing["metadata_url"])
    except ValidationError:
        raise

    # Update IdP with new metadata
    row = database.saml.update_idp_metadata_fields(
        tenant_id=tenant_id,
        idp_id=idp_id,
        entity_id=metadata.entity_id,
        sso_url=metadata.sso_url,
        certificate_pem=metadata.certificate_pem,
        slo_url=metadata.slo_url,
    )

    if row is None:
        raise ValidationError(
            message="Failed to update identity provider",
            code="idp_update_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_metadata_refreshed",
        metadata={"name": existing["name"], "manual": True},
        request_metadata=requesting_user.get("request_metadata"),
    )

    return _idp_row_to_config(row)


def refresh_all_idp_metadata() -> MetadataRefreshSummary:
    """
    Refresh metadata for all IdPs that have a metadata URL.

    Used by background job. No authorization required.

    Returns:
        MetadataRefreshSummary with results for each IdP
    """
    idps = database.saml.get_idps_with_metadata_url()
    results: list[MetadataRefreshResult] = []
    successful = 0
    failed = 0

    for idp in idps:
        idp_id = str(idp["id"])
        tenant_id = str(idp["tenant_id"])
        idp_name = idp["name"]
        metadata_url = idp["metadata_url"]

        try:
            # Fetch and parse metadata
            metadata = fetch_and_parse_idp_metadata(metadata_url)

            # Get current values to determine what changed
            current = database.saml.get_identity_provider(tenant_id, idp_id)
            if current is None:
                raise ValueError("IdP not found")

            updated_fields = []
            if current["entity_id"] != metadata.entity_id:
                updated_fields.append("entity_id")
            if current["sso_url"] != metadata.sso_url:
                updated_fields.append("sso_url")
            if current["slo_url"] != metadata.slo_url:
                updated_fields.append("slo_url")
            if current["certificate_pem"] != metadata.certificate_pem:
                updated_fields.append("certificate_pem")

            # Update IdP with new metadata
            # NOTE: No log_event here - background metadata sync is exempt from audit
            # logging. These are automated system operations, not user actions.
            database.saml.update_idp_metadata_fields(
                tenant_id=tenant_id,
                idp_id=idp_id,
                entity_id=metadata.entity_id,
                sso_url=metadata.sso_url,
                certificate_pem=metadata.certificate_pem,
                slo_url=metadata.slo_url,
            )

            results.append(
                MetadataRefreshResult(
                    idp_id=idp_id,
                    idp_name=idp_name,
                    success=True,
                    updated_fields=updated_fields if updated_fields else None,
                )
            )
            successful += 1

            logger.info(f"Refreshed SAML metadata for IdP {idp_name} ({idp_id})")

        except Exception as e:
            error_msg = str(e)[:200]  # Truncate long errors

            # Set error on IdP (but don't disable it)
            # NOTE: No log_event - background sync errors are exempt from audit logging
            database.saml.set_idp_metadata_error(tenant_id, idp_id, error_msg)

            results.append(
                MetadataRefreshResult(
                    idp_id=idp_id,
                    idp_name=idp_name,
                    success=False,
                    error=error_msg,
                )
            )
            failed += 1

            logger.warning(f"Failed to refresh SAML metadata for IdP {idp_name}: {error_msg}")

    return MetadataRefreshSummary(
        total=len(idps),
        successful=successful,
        failed=failed,
        results=results,
    )


# ============================================================================
# SAML Authentication Flow
# ============================================================================


def get_enabled_idps_for_login(tenant_id: str) -> list[IdPForLogin]:
    """
    Get enabled IdPs for login page display.

    No authorization required (used on login page).
    """
    rows = database.saml.get_enabled_identity_providers(tenant_id)
    return [
        IdPForLogin(
            id=str(row["id"]),
            name=row["name"],
            provider_type=row["provider_type"],
        )
        for row in rows
    ]


def get_default_idp(tenant_id: str) -> IdPConfig | None:
    """
    Get the default IdP for the tenant.

    No authorization required.
    """
    row = database.saml.get_default_identity_provider(tenant_id)
    return _idp_row_to_config(row) if row else None


def get_idp_for_saml_login(tenant_id: str, idp_id: str) -> IdPConfig:
    """
    Get IdP configuration for SAML login by IdP ID.

    Validates that the IdP exists and is enabled.

    No authorization required (used during login flow).
    """
    row = database.saml.get_identity_provider(tenant_id, idp_id)

    if row is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    if not row["is_enabled"]:
        raise ForbiddenError(
            message="Identity provider is not enabled",
            code="idp_disabled",
        )

    return _idp_row_to_config(row)


def get_idp_by_issuer(tenant_id: str, issuer: str) -> IdPConfig:
    """
    Get IdP configuration by issuer (entity_id).

    Used to look up the IdP from a SAML response's Issuer field.
    Validates that the IdP exists and is enabled.

    No authorization required (used during login flow).

    Args:
        tenant_id: Tenant ID
        issuer: The Issuer entity ID from the SAML response

    Returns:
        IdPConfig for the matching IdP

    Raises:
        NotFoundError if no IdP matches the issuer
        ForbiddenError if the IdP is disabled
    """
    row = database.saml.get_identity_provider_by_entity_id(tenant_id, issuer)

    if row is None:
        raise NotFoundError(
            message="Identity provider not found for issuer",
            code="idp_issuer_not_found",
            details={"issuer": issuer},
        )

    if not row["is_enabled"]:
        raise ForbiddenError(
            message="Identity provider is not enabled",
            code="idp_disabled",
        )

    return _idp_row_to_config(row)


def build_authn_request(
    tenant_id: str,
    idp_id: str,
    relay_state: str | None = None,
) -> tuple[str, str]:
    """
    Build SAML AuthnRequest and return redirect URL.

    No authorization required (used during login flow).

    Args:
        tenant_id: Tenant ID
        idp_id: IdP ID to authenticate with
        relay_state: Optional state to preserve through SAML flow

    Returns:
        Tuple of (redirect_url, request_id)
        request_id should be stored in session for response validation
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from utils.saml import build_saml_settings

    # Get IdP and SP certificate
    idp = get_idp_for_saml_login(tenant_id, idp_id)
    sp_cert = database.saml.get_sp_certificate(tenant_id)

    if sp_cert is None:
        raise NotFoundError(
            message="SP certificate not configured",
            code="sp_certificate_not_found",
        )

    # Decrypt SP private key
    sp_private_key = decrypt_private_key(sp_cert["private_key_pem_enc"])

    # Derive ACS URL from SP entity ID (standard: single ACS for all IdPs)
    # sp_entity_id is "{base_url}/saml/metadata", so we derive ACS as "{base_url}/saml/acs"
    sp_acs_url = idp.sp_entity_id.replace("/saml/metadata", "/saml/acs")

    # Build settings
    settings = build_saml_settings(
        sp_entity_id=idp.sp_entity_id,
        sp_acs_url=sp_acs_url,
        sp_certificate_pem=sp_cert["certificate_pem"],
        sp_private_key_pem=sp_private_key,
        idp_entity_id=idp.entity_id,
        idp_sso_url=idp.sso_url,
        idp_certificate_pem=idp.certificate_pem,
        idp_slo_url=idp.slo_url,
    )

    # Create mock request dict for python3-saml
    # We need to provide the expected format for the library
    request_data = {
        "https": "on",
        "http_host": "",  # Will be set from actual request
        "script_name": "",
        "get_data": {},
        "post_data": {},
    }

    auth = OneLogin_Saml2_Auth(request_data, settings)

    # Generate AuthnRequest
    redirect_url = auth.login(relay_state or "")

    # Get the request ID for validation
    request_id = auth.get_last_request_id()

    return redirect_url, request_id


def process_saml_response(
    tenant_id: str,
    idp_id: str,
    saml_response: str,
    request_id: str | None = None,
    request_data: dict | None = None,
) -> SAMLAuthResult:
    """
    Process and validate SAML response from IdP.

    Performs:
    - Signature validation (required, unsigned rejected)
    - NotOnOrAfter validation (replay prevention)
    - Attribute extraction

    No authorization required (used during login flow).

    Args:
        tenant_id: Tenant ID
        idp_id: IdP ID that sent the response
        saml_response: Base64-encoded SAML response
        request_id: Expected request ID (from session) for InResponseTo validation
        request_data: Request data dict for python3-saml

    Returns:
        SAMLAuthResult with attributes and authentication status

    Raises:
        ValidationError for invalid signatures, expired assertions, etc.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from utils.saml import build_saml_settings

    # Get IdP and SP certificate
    idp = get_idp_for_saml_login(tenant_id, idp_id)
    sp_cert = database.saml.get_sp_certificate(tenant_id)

    if sp_cert is None:
        raise NotFoundError(
            message="SP certificate not configured",
            code="sp_certificate_not_found",
        )

    # Decrypt SP private key
    sp_private_key = decrypt_private_key(sp_cert["private_key_pem_enc"])

    # Derive ACS URL from SP entity ID (standard: single ACS for all IdPs)
    sp_acs_url = idp.sp_entity_id.replace("/saml/metadata", "/saml/acs")

    # Build settings
    settings = build_saml_settings(
        sp_entity_id=idp.sp_entity_id,
        sp_acs_url=sp_acs_url,
        sp_certificate_pem=sp_cert["certificate_pem"],
        sp_private_key_pem=sp_private_key,
        idp_entity_id=idp.entity_id,
        idp_sso_url=idp.sso_url,
        idp_certificate_pem=idp.certificate_pem,
        idp_slo_url=idp.slo_url,
    )

    # Create request data for python3-saml
    if request_data is None:
        request_data = {
            "https": "on",
            "http_host": "",
            "script_name": "",
            "get_data": {},
            "post_data": {"SAMLResponse": saml_response},
        }
    else:
        request_data["post_data"] = {"SAMLResponse": saml_response}

    auth = OneLogin_Saml2_Auth(request_data, settings)

    # Process the response
    auth.process_response(request_id=request_id)

    # Check for errors
    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason()
        raise ValidationError(
            message=f"SAML response validation failed: {error_reason or ', '.join(errors)}",
            code="saml_validation_failed",
            details={"errors": errors},
        )

    # Verify the response was authenticated
    if not auth.is_authenticated():
        raise ValidationError(
            message="SAML authentication failed",
            code="saml_auth_failed",
        )

    # Extract attributes using IdP's attribute mapping
    raw_attributes = auth.get_attributes()
    name_id = auth.get_nameid()

    # Map attributes using IdP configuration
    mapping = idp.attribute_mapping
    email = _get_saml_attribute(raw_attributes, mapping.get("email", "email"))
    first_name = _get_saml_attribute(raw_attributes, mapping.get("first_name", "firstName"))
    last_name = _get_saml_attribute(raw_attributes, mapping.get("last_name", "lastName"))

    if not email:
        raise ValidationError(
            message="SAML response missing email attribute",
            code="saml_missing_email",
        )

    return SAMLAuthResult(
        attributes=SAMLAttributes(
            email=email,
            first_name=first_name,
            last_name=last_name,
            name_id=name_id,
        ),
        session_index=auth.get_session_index(),
        idp_id=idp_id,
        requires_mfa=idp.require_platform_mfa,
    )


def process_saml_test_response(
    tenant_id: str,
    idp_id: str,
    saml_response: str,
    request_id: str | None = None,
    request_data: dict | None = None,
) -> SAMLTestResult:
    """
    Process SAML response for connection testing.

    Similar to process_saml_response() but:
    - Returns SAMLTestResult instead of raising exceptions
    - Includes all raw attributes for display
    - Does NOT create session or provision users

    No authorization required (used during test flow).

    Args:
        tenant_id: Tenant ID
        idp_id: IdP ID that sent the response
        saml_response: Base64-encoded SAML response
        request_id: Expected request ID (from session) for InResponseTo validation
        request_data: Request data dict for python3-saml

    Returns:
        SAMLTestResult with success status and assertion details or error info
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from utils.saml import build_saml_settings

    logger = logging.getLogger(__name__)

    try:
        # Get IdP and SP certificate
        idp = get_idp_for_saml_login(tenant_id, idp_id)
        sp_cert = database.saml.get_sp_certificate(tenant_id)

        if sp_cert is None:
            return SAMLTestResult(
                success=False,
                error_type="configuration_error",
                error_detail="SP certificate not configured",
            )

        # Decrypt SP private key and build settings
        sp_private_key = decrypt_private_key(sp_cert["private_key_pem_enc"])
        sp_acs_url = idp.sp_entity_id.replace("/saml/metadata", "/saml/acs")

        settings = build_saml_settings(
            sp_entity_id=idp.sp_entity_id,
            sp_acs_url=sp_acs_url,
            sp_certificate_pem=sp_cert["certificate_pem"],
            sp_private_key_pem=sp_private_key,
            idp_entity_id=idp.entity_id,
            idp_sso_url=idp.sso_url,
            idp_certificate_pem=idp.certificate_pem,
            idp_slo_url=idp.slo_url,
        )

        # Create request data for python3-saml
        if request_data is None:
            request_data = {
                "https": "on",
                "http_host": "",
                "script_name": "",
                "get_data": {},
                "post_data": {"SAMLResponse": saml_response},
            }
        else:
            request_data["post_data"] = {"SAMLResponse": saml_response}

        auth = OneLogin_Saml2_Auth(request_data, settings)
        auth.process_response(request_id=request_id)

        # Check for errors
        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason()
            error_str = str(error_reason).lower() if error_reason else ""

            # Categorize error type
            if "signature" in error_str:
                error_type = "signature_error"
            elif "expired" in error_str or "notonorafter" in error_str:
                error_type = "expired"
            else:
                error_type = "invalid_response"

            return SAMLTestResult(
                success=False,
                error_type=error_type,
                error_detail=error_reason or ", ".join(errors),
            )

        if not auth.is_authenticated():
            return SAMLTestResult(
                success=False,
                error_type="auth_failed",
                error_detail="SAML authentication failed",
            )

        # Extract all attributes for display
        raw_attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        name_id_format = auth.get_nameid_format()
        session_index = auth.get_session_index()

        # Parse using IdP mapping
        mapping = idp.attribute_mapping
        parsed_email = _get_saml_attribute(raw_attributes, mapping.get("email", "email"))
        parsed_first_name = _get_saml_attribute(
            raw_attributes, mapping.get("first_name", "firstName")
        )
        parsed_last_name = _get_saml_attribute(raw_attributes, mapping.get("last_name", "lastName"))

        return SAMLTestResult(
            success=True,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
            attributes=raw_attributes,
            parsed_email=parsed_email,
            parsed_first_name=parsed_first_name,
            parsed_last_name=parsed_last_name,
        )

    except NotFoundError as e:
        return SAMLTestResult(
            success=False,
            error_type="idp_not_found",
            error_detail=str(e),
        )
    except ForbiddenError as e:
        return SAMLTestResult(
            success=False,
            error_type="idp_disabled",
            error_detail=str(e),
        )
    except Exception as e:
        logger.exception("SAML test failed with unexpected error")
        return SAMLTestResult(
            success=False,
            error_type="unexpected_error",
            error_detail=str(e),
        )


def _get_saml_attribute(attributes: dict, attr_name: str) -> str | None:
    """Extract a SAML attribute value (handles list values)."""
    value = attributes.get(attr_name)
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return str(value)


def _jit_provision_user(
    tenant_id: str,
    saml_result: SAMLAuthResult,
    idp: dict,
) -> dict:
    """
    Create a new user via JIT provisioning from SAML assertion.

    Creates user with:
    - Email from SAML assertion (verified, since IdP is authoritative)
    - First/last name from SAML attributes (or defaults)
    - Role: member (default)
    - Password: NULL (SAML-only authentication)
    - saml_idp_id: Links user to provisioning IdP

    Args:
        tenant_id: Tenant ID
        saml_result: Processed SAML response with attributes
        idp: IdP dict with configuration

    Returns:
        User dict for session creation

    Raises:
        ValidationError if user creation fails
    """
    from services import users as users_service

    attrs = saml_result.attributes

    # Extract names, with sensible defaults
    first_name = attrs.first_name or "SAML"
    last_name = attrs.last_name or "User"
    email = attrs.email

    # Race condition protection: Check if email was created between
    # our check and now (another concurrent request)
    if users_service.email_exists(tenant_id, email):
        user = database.users.get_user_by_email_with_status(tenant_id, email)
        if user:
            return user
        raise ValidationError(
            message="Failed to retrieve user after race condition",
            code="jit_user_retrieval_failed",
        )

    # Create user record (no password - SAML-only authentication)
    result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        role="member",
    )

    if not result:
        raise ValidationError(
            message="Failed to create user via JIT provisioning",
            code="jit_user_creation_failed",
        )

    user_id = str(result["user_id"])

    # Add verified email (SAML assertion from trusted IdP is authoritative)
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        is_primary=True,
    )

    # Link user to the IdP that provisioned them
    database.saml.set_user_idp(tenant_id, user_id, saml_result.idp_id)

    # Log JIT provisioning event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_created_jit",
        metadata={
            "idp_id": saml_result.idp_id,
            "idp_name": idp["name"],
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "name_id": attrs.name_id,
        },
        request_metadata=None,
    )

    # Fetch and return the created user for session creation
    user = database.users.get_user_by_email_with_status(tenant_id, email)
    if not user:
        raise ValidationError(
            message="Failed to retrieve created user",
            code="jit_user_retrieval_failed",
        )

    return user


def authenticate_via_saml(
    tenant_id: str,
    saml_result: SAMLAuthResult,
) -> dict:
    """
    Complete SAML authentication and return user.

    - Looks up user by email from SAML attributes
    - If user doesn't exist and JIT provisioning is enabled, creates user
    - Checks user status (not inactivated)
    - Wipes password if exists (SAML users are "locked in")
    - Links user to IdP if not already
    - Returns user dict for session creation

    Security: Once a user authenticates via SAML, their password is wiped.
    This prevents reverting to password auth. MFA info is preserved.

    Logs: user_signed_in_saml event (or user_created_jit for new users).

    Args:
        tenant_id: Tenant ID
        saml_result: Processed SAML response

    Returns:
        User dict for session creation

    Raises:
        NotFoundError if user doesn't exist and JIT is disabled
        ForbiddenError if user is inactivated
    """
    email = saml_result.attributes.email

    # Look up user by email
    user = database.users.get_user_by_email_with_status(tenant_id, email)

    if user is None:
        # Check if JIT provisioning is enabled for this IdP
        idp = database.saml.get_identity_provider(tenant_id, saml_result.idp_id)

        if idp is None or not idp.get("jit_provisioning"):
            raise NotFoundError(
                message="User account not found",
                code="user_not_found",
                details={"email": email},
            )

        # JIT provision the user (logs user_created_jit event internally)
        user = _jit_provision_user(
            tenant_id=tenant_id,
            saml_result=saml_result,
            idp=idp,
        )

        # Return immediately - JIT provisioning already logged the creation event
        # No need to log sign-in since this is their first login (creation implies sign-in)
        return user

    # Check user status
    if user.get("inactivated_at"):
        raise ForbiddenError(
            message="User account is inactivated",
            code="user_inactivated",
        )

    user_id = str(user["id"])

    # Security: Wipe password on SAML auth (user is now "locked in" to SAML)
    # MFA info is preserved - IdP may require additional platform MFA
    if user.get("password_hash"):
        database.users.wipe_user_password(tenant_id, user_id)
        logger.info(f"Password wiped for user {user_id} after SAML authentication")

    # Ensure user is linked to this IdP
    current_idp_id = user.get("saml_idp_id")
    if current_idp_id != saml_result.idp_id:
        database.saml.set_user_idp(tenant_id, user_id, saml_result.idp_id)

    # Log the sign-in event (for existing users)
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_signed_in_saml",
        metadata={
            "idp_id": saml_result.idp_id,
            "email": email,
            "password_wiped": bool(user.get("password_hash")),
        },
        request_metadata=None,  # Will be added by router
    )

    return user


# ============================================================================
# Domain Binding Operations (Phase 3)
# ============================================================================


def list_domain_bindings(
    requesting_user: RequestingUser,
    idp_id: str,
) -> DomainBindingList:
    """
    List domains bound to a specific IdP.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user
        idp_id: IdP UUID to list bindings for

    Returns:
        DomainBindingList with bound domains
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    rows = database.saml.get_domain_bindings_for_idp(tenant_id, idp_id)
    items = [
        DomainBinding(
            id=str(row["id"]),
            domain_id=str(row["domain_id"]),
            domain=row["domain"],
            idp_id=str(row["idp_id"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]

    return DomainBindingList(items=items)


def bind_domain_to_idp(
    requesting_user: RequestingUser,
    idp_id: str,
    domain_id: str,
) -> DomainBinding:
    """
    Bind a privileged domain to an IdP and assign all matching users.

    Immediately assigns all users with verified emails in this domain
    to the IdP and wipes their passwords. This is a permanent assignment.

    Authorization: Requires super_admin role.
    Logs: saml_domain_bound event + user_saml_idp_assigned for each user.

    Args:
        requesting_user: The authenticated user
        idp_id: IdP UUID to bind domain to
        domain_id: Privileged domain UUID to bind

    Returns:
        Created DomainBinding
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    idp = database.saml.get_identity_provider(tenant_id, idp_id)
    if idp is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Verify domain exists
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    # Get all users with emails in this domain who don't already have this IdP
    users_in_domain = database.users.get_users_by_email_domain(tenant_id, domain["domain"])
    users_to_assign = [
        u
        for u in users_in_domain
        if u.get("saml_idp_id") is None or str(u["saml_idp_id"]) != idp_id
    ]

    # Assign all matching users to this IdP (wipes passwords)
    user_ids_to_assign = [str(u["id"]) for u in users_to_assign]
    if user_ids_to_assign:
        database.users.bulk_assign_users_to_idp(tenant_id, user_ids_to_assign, idp_id)
        logger.info(
            f"Domain binding: assigned {len(user_ids_to_assign)} users "
            f"from {domain['domain']} to IdP {idp['name']}"
        )

    # Create binding (upsert - replaces existing binding if any)
    row = database.saml.bind_domain_to_idp(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        idp_id=idp_id,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to bind domain to IdP",
            code="domain_binding_failed",
        )

    # Log domain binding event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_domain_binding",
        artifact_id=str(row["id"]),
        event_type="saml_domain_bound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "idp_id": idp_id,
            "idp_name": idp["name"],
            "users_assigned": len(user_ids_to_assign),
        },
        request_metadata=requesting_user.get("request_metadata"),
    )

    # Log individual user assignments
    for user_id in user_ids_to_assign:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_saml_idp_assigned",
            metadata={
                "saml_idp_id": idp_id,
                "idp_name": idp["name"],
                "assigned_via": "domain_binding",
                "domain": domain["domain"],
                "password_wiped": True,
            },
            request_metadata=requesting_user.get("request_metadata"),
        )

    return DomainBinding(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        domain=domain["domain"],
        idp_id=str(row["idp_id"]),
        created_at=row["created_at"],
    )


def unbind_domain_from_idp(
    requesting_user: RequestingUser,
    domain_id: str,
) -> None:
    """
    Unbind a domain from its IdP.

    This only removes the domain binding record. Users who were assigned
    to the IdP via this binding keep their IdP assignments (they were
    explicitly assigned when the domain was bound).

    New users with this domain will no longer be auto-assigned to the IdP.

    Authorization: Requires super_admin role.
    Logs: saml_domain_unbound event.

    Args:
        requesting_user: The authenticated user
        domain_id: Domain UUID to unbind
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get the binding
    binding = database.saml.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if binding is None:
        raise NotFoundError(
            message="Domain binding not found",
            code="domain_binding_not_found",
        )

    # Get the domain for logging
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    database.saml.unbind_domain_from_idp(tenant_id, domain_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_domain_binding",
        artifact_id=str(binding["id"]),
        event_type="saml_domain_unbound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "previous_idp_id": str(binding["idp_id"]),
        },
        request_metadata=requesting_user.get("request_metadata"),
    )


def rebind_domain_to_idp(
    requesting_user: RequestingUser,
    domain_id: str,
    new_idp_id: str,
) -> DomainBinding:
    """
    Rebind a domain from one IdP to another, moving all affected users.

    Users with emails in this domain who are currently assigned to the
    old IdP are reassigned to the new IdP.

    Authorization: Requires super_admin role.
    Logs: saml_domain_rebound event + user_saml_idp_assigned for each moved user.

    Args:
        requesting_user: The authenticated user
        domain_id: Domain UUID to rebind
        new_idp_id: New IdP UUID to bind to

    Returns:
        Updated DomainBinding
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get the current binding
    current_binding = database.saml.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if current_binding is None:
        raise NotFoundError(
            message="Domain binding not found",
            code="domain_binding_not_found",
        )

    # Verify new IdP exists
    new_idp = database.saml.get_identity_provider(tenant_id, new_idp_id)
    if new_idp is None:
        raise NotFoundError(
            message="Target identity provider not found",
            code="idp_not_found",
        )

    # Get domain info
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    previous_idp_id = str(current_binding["idp_id"])

    # Find users with this domain who are currently on the old IdP
    users_in_domain = database.users.get_users_by_email_domain(tenant_id, domain["domain"])
    users_to_move = [
        u
        for u in users_in_domain
        if u.get("saml_idp_id") is not None and str(u["saml_idp_id"]) == previous_idp_id
    ]

    # Move users to new IdP (they already have no passwords from original binding)
    user_ids_to_move = [str(u["id"]) for u in users_to_move]
    if user_ids_to_move:
        # Use bulk update - no need to wipe passwords (already wiped)
        for user_id in user_ids_to_move:
            database.users.update_user_saml_idp(tenant_id, user_id, new_idp_id)
        logger.info(
            f"Domain rebind: moved {len(user_ids_to_move)} users "
            f"from IdP {previous_idp_id} to {new_idp['name']}"
        )

    # Update binding (upsert handles the update)
    row = database.saml.bind_domain_to_idp(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        idp_id=new_idp_id,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to rebind domain",
            code="domain_rebind_failed",
        )

    # Log domain rebind event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_domain_binding",
        artifact_id=str(row["id"]),
        event_type="saml_domain_rebound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "previous_idp_id": previous_idp_id,
            "new_idp_id": new_idp_id,
            "new_idp_name": new_idp["name"],
            "users_moved": len(user_ids_to_move),
        },
        request_metadata=requesting_user.get("request_metadata"),
    )

    # Log individual user moves
    for user_id in user_ids_to_move:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_saml_idp_assigned",
            metadata={
                "saml_idp_id": new_idp_id,
                "idp_name": new_idp["name"],
                "assigned_via": "domain_rebind",
                "domain": domain["domain"],
                "previous_idp_id": previous_idp_id,
            },
            request_metadata=requesting_user.get("request_metadata"),
        )

    return DomainBinding(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        domain=domain["domain"],
        idp_id=str(row["idp_id"]),
        created_at=row["created_at"],
    )


def get_unbound_domains(
    requesting_user: RequestingUser,
) -> list[UnboundDomain]:
    """
    Get privileged domains not bound to any IdP.

    Authorization: Requires super_admin role.

    Returns:
        List of UnboundDomain
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.saml.get_unbound_domains(requesting_user["tenant_id"])

    return [
        UnboundDomain(
            id=str(row["id"]),
            domain=row["domain"],
        )
        for row in rows
    ]


# ============================================================================
# User IdP Assignment (Phase 3)
# ============================================================================


def assign_user_idp(
    requesting_user: RequestingUser,
    user_id: str,
    saml_idp_id: str | None,
) -> None:
    """
    Assign a user to an IdP or set them as a password-only user.

    Every user must be either:
    - Password user (saml_idp_id = NULL) - authenticates with password
    - IdP user (saml_idp_id = UUID) - authenticates via SAML

    Security constraints:
    - If assigning to IdP: wipe password (keep MFA)
    - If removing from IdP (setting to NULL): inactivate + unverify emails

    Authorization: Requires super_admin role.
    Logs: user_saml_idp_assigned event.

    Args:
        requesting_user: The authenticated user
        user_id: User UUID to update
        saml_idp_id: IdP UUID to assign, or None for password-only
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get current user state
    user = database.users.get_user_with_saml_info(tenant_id, user_id)
    if user is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    # Verify IdP exists if specified
    idp_name = None
    if saml_idp_id is not None:
        idp = database.saml.get_identity_provider(tenant_id, saml_idp_id)
        if idp is None:
            raise NotFoundError(
                message="Identity provider not found",
                code="idp_not_found",
            )
        idp_name = idp["name"]

    current_idp_id = user.get("saml_idp_id")

    # Determine state changes
    had_idp = current_idp_id is not None
    will_have_idp = saml_idp_id is not None

    # Security: Wipe password when assigning to IdP
    if will_have_idp:
        database.users.wipe_user_password(tenant_id, user_id)
        logger.info(f"Password wiped for user {user_id} on IdP assignment")

    # Security: Inactivate + unverify when removing from IdP (not when moving to another)
    user_inactivated = False
    if had_idp and not will_have_idp:
        database.users.unverify_user_emails(tenant_id, user_id)
        database.users.inactivate_user(tenant_id, user_id)
        user_inactivated = True
        logger.info(f"User {user_id} inactivated after being removed from IdP")

    # Update user's IdP assignment
    database.users.update_user_saml_idp(
        tenant_id=tenant_id,
        user_id=user_id,
        saml_idp_id=saml_idp_id,
    )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_saml_idp_assigned",
        metadata={
            "saml_idp_id": saml_idp_id,
            "idp_name": idp_name,
            "previous_idp_id": str(current_idp_id) if current_idp_id else None,
            "password_wiped": will_have_idp,
            "user_inactivated": user_inactivated,
        },
        request_metadata=requesting_user.get("request_metadata"),
    )


# ============================================================================
# Authentication Routing (Phase 3)
# ============================================================================


def determine_auth_route(
    tenant_id: str,
    email: str,
) -> AuthRouteResult:
    """
    Determine authentication route for an email address.

    Used during email-first login flow to decide whether to show
    password form or redirect to IdP.

    Every user is either:
    - Password user (saml_idp_id = NULL) → route to password form
    - IdP user (saml_idp_id = UUID) → route to that IdP

    For unknown users:
    - If domain is bound to IdP with JIT → route to domain's IdP
    - If default IdP has JIT → route to default IdP
    - Otherwise → not found

    Args:
        tenant_id: Tenant ID
        email: Email address to check

    Returns:
        AuthRouteResult with route_type and optional idp info
    """
    # Extract domain from email
    if "@" not in email:
        return AuthRouteResult(
            route_type="invalid_email",
        )

    email_domain = email.split("@")[1].lower()

    # Look up user
    user = database.users.get_user_auth_info(tenant_id, email)

    if user is not None:
        user_id = str(user["id"])

        # Check if user is inactivated
        if user.get("is_inactivated"):
            return AuthRouteResult(
                route_type="inactivated",
                user_id=user_id,
            )

        # User has IdP assigned → route to that IdP
        if user.get("saml_idp_id"):
            idp = database.saml.get_identity_provider(tenant_id, str(user["saml_idp_id"]))
            if idp and idp.get("is_enabled"):
                return AuthRouteResult(
                    route_type="idp",
                    idp_id=str(user["saml_idp_id"]),
                    idp_name=idp["name"],
                    user_id=user_id,
                )
            else:
                # IdP exists but disabled - user can't authenticate
                return AuthRouteResult(
                    route_type="idp_disabled",
                    user_id=user_id,
                )

        # User has password → route to password form
        if user.get("has_password"):
            return AuthRouteResult(
                route_type="password",
                user_id=user_id,
            )

        # User exists but has no password and no IdP - should not happen
        # but handle gracefully
        return AuthRouteResult(
            route_type="no_auth_method",
            user_id=user_id,
        )

    # User doesn't exist - check for JIT provisioning routes

    # Domain bound to IdP with JIT enabled
    domain_idp = database.saml.get_idp_for_domain(tenant_id, email_domain)
    if domain_idp and domain_idp.get("is_enabled") and domain_idp.get("jit_provisioning"):
        return AuthRouteResult(
            route_type="idp_jit",
            idp_id=str(domain_idp["id"]),
            idp_name=domain_idp["name"],
        )

    # Tenant default IdP with JIT enabled
    default_idp = database.saml.get_default_identity_provider(tenant_id)
    if default_idp and default_idp.get("is_enabled") and default_idp.get("jit_provisioning"):
        return AuthRouteResult(
            route_type="idp_jit",
            idp_id=str(default_idp["id"]),
            idp_name=default_idp["name"],
        )

    # No user and no JIT route
    return AuthRouteResult(
        route_type="not_found",
    )
