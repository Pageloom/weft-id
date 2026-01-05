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
    SPCertificate,
    SPMetadata,
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
        sp_entity_id=row["sp_entity_id"],
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

    # TODO: Check if any users are assigned to this IdP

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


def _get_saml_attribute(attributes: dict, attr_name: str) -> str | None:
    """Extract a SAML attribute value (handles list values)."""
    value = attributes.get(attr_name)
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return str(value)


def authenticate_via_saml(
    tenant_id: str,
    saml_result: SAMLAuthResult,
) -> dict:
    """
    Complete SAML authentication and return user.

    - Looks up user by email from SAML attributes
    - Checks user status (not inactivated)
    - Returns user dict for session creation

    Logs: user_signed_in_saml event.

    Args:
        tenant_id: Tenant ID
        saml_result: Processed SAML response

    Returns:
        User dict for session creation

    Raises:
        NotFoundError if user doesn't exist (JIT disabled)
        ForbiddenError if user is inactivated
    """
    email = saml_result.attributes.email

    # Look up user by email
    user = database.users.get_user_by_email_with_status(tenant_id, email)

    if user is None:
        # TODO: Implement JIT provisioning check here
        raise NotFoundError(
            message="User account not found",
            code="user_not_found",
            details={"email": email},
        )

    # Check user status
    if user.get("inactivated_at"):
        raise ForbiddenError(
            message="User account is inactivated",
            code="user_inactivated",
        )

    # Log the sign-in event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user["id"]),
        artifact_type="user",
        artifact_id=str(user["id"]),
        event_type="user_signed_in_saml",
        metadata={
            "idp_id": saml_result.idp_id,
            "email": email,
        },
        request_metadata=None,  # Will be added by router
    )

    return user
