"""Downstream SAML Service Provider management.

This module handles registration and deletion of downstream SPs
that authenticate users via SSO against this platform.
"""

import logging

import database
from schemas.service_providers import (
    SPConfig,
    SPCreate,
    SPListItem,
    SPListResponse,
    SPMetadataURLInfo,
    SPSigningCertificate,
    SPSigningCertificateRotationResult,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.types import RequestingUser
from utils.saml_idp import generate_idp_metadata_xml

logger = logging.getLogger(__name__)


# ============================================================================
# Row Converters
# ============================================================================


def _row_to_config(row: dict) -> SPConfig:
    """Convert database row to SPConfig schema."""
    return SPConfig(
        id=str(row["id"]),
        name=row["name"],
        entity_id=row["entity_id"],
        acs_url=row["acs_url"],
        certificate_pem=row.get("certificate_pem"),
        nameid_format=row["nameid_format"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_list_item(row: dict, signing_cert_expires_at=None) -> SPListItem:
    """Convert database row to SPListItem schema."""
    return SPListItem(
        id=str(row["id"]),
        name=row["name"],
        entity_id=row["entity_id"],
        signing_cert_expires_at=signing_cert_expires_at,
        created_at=row["created_at"],
    )


# ============================================================================
# Internal Helpers
# ============================================================================


def _get_or_create_sp_signing_certificate(
    tenant_id: str,
    sp_id: str,
    created_by: str,
) -> dict:
    """Get existing per-SP signing cert or generate a new one.

    Returns the certificate database row dict.
    """
    from utils.saml import encrypt_private_key, generate_sp_certificate, get_certificate_expiry

    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        return cert

    cert_pem, key_pem = generate_sp_certificate(tenant_id)
    encrypted_key = encrypt_private_key(key_pem)
    expires_at = get_certificate_expiry(cert_pem)

    cert = database.sp_signing_certificates.create_signing_certificate(
        tenant_id=tenant_id,
        sp_id=sp_id,
        tenant_id_value=tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=created_by,
    )

    if cert is None:
        raise ValidationError(
            message="Failed to create SP signing certificate",
            code="sp_signing_certificate_creation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=created_by,
        artifact_type="sp_signing_certificate",
        artifact_id=str(cert["id"]),
        event_type="sp_signing_certificate_created",
        metadata={"sp_id": sp_id, "expires_at": str(expires_at)},
    )

    return cert


# ============================================================================
# SP CRUD Operations
# ============================================================================


def list_service_providers(
    requesting_user: RequestingUser,
) -> SPListResponse:
    """List all SPs for the tenant.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    rows = database.service_providers.list_service_providers(tenant_id)

    # Enrich each SP with signing cert expiry
    items = []
    for row in rows:
        sp_id = str(row["id"])
        cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
        cert_expires = cert["expires_at"] if cert else None
        items.append(_row_to_list_item(row, signing_cert_expires_at=cert_expires))

    return SPListResponse(items=items, total=len(items))


def get_service_provider(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPConfig:
    """Get a single SP configuration.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    row = database.service_providers.get_service_provider(tenant_id, sp_id)

    if row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    config = _row_to_config(row)

    # Enrich with signing cert expiry
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]

    return config


def create_service_provider(
    requesting_user: RequestingUser,
    data: SPCreate,
) -> SPConfig:
    """Create a new SP from manual entry.

    Authorization: Requires super_admin role.
    Logs: service_provider_created event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Check for duplicate entity_id
    existing = database.service_providers.get_service_provider_by_entity_id(
        tenant_id, data.entity_id
    )
    if existing:
        raise ConflictError(
            message=f"A service provider with entity ID '{data.entity_id}' already exists",
            code="sp_entity_id_exists",
        )

    row = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=data.name,
        entity_id=data.entity_id,
        acs_url=data.acs_url,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to create service provider",
            code="sp_creation_failed",
        )

    sp_id = str(row["id"])

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_created",
        metadata={
            "name": data.name,
            "entity_id": data.entity_id,
            "method": "manual",
        },
    )

    # Eagerly generate per-SP signing certificate
    _get_or_create_sp_signing_certificate(tenant_id, sp_id, requesting_user["id"])

    return _row_to_config(row)


def import_sp_from_metadata_xml(
    requesting_user: RequestingUser,
    name: str,
    metadata_xml: str,
) -> SPConfig:
    """Import an SP from pasted metadata XML.

    Authorization: Requires super_admin role.
    Logs: service_provider_created event.
    """
    from utils.saml_idp import parse_sp_metadata_xml

    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Parse metadata
    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="sp_metadata_parse_error",
        )

    # Check for duplicate entity_id
    existing = database.service_providers.get_service_provider_by_entity_id(
        tenant_id, parsed["entity_id"]
    )
    if existing:
        raise ConflictError(
            message=f"A service provider with entity ID '{parsed['entity_id']}' already exists",
            code="sp_entity_id_exists",
        )

    row = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        entity_id=parsed["entity_id"],
        acs_url=parsed["acs_url"],
        certificate_pem=parsed.get("certificate_pem"),
        nameid_format=parsed.get(
            "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        metadata_xml=metadata_xml,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to create service provider",
            code="sp_creation_failed",
        )

    sp_id = str(row["id"])

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_created",
        metadata={
            "name": name,
            "entity_id": parsed["entity_id"],
            "method": "metadata_xml",
        },
    )

    # Eagerly generate per-SP signing certificate
    _get_or_create_sp_signing_certificate(tenant_id, sp_id, requesting_user["id"])

    return _row_to_config(row)


def import_sp_from_metadata_url(
    requesting_user: RequestingUser,
    name: str,
    metadata_url: str,
) -> SPConfig:
    """Import an SP from a metadata URL.

    Authorization: Requires super_admin role.
    Logs: service_provider_created event.
    """
    from utils.saml_idp import fetch_sp_metadata, parse_sp_metadata_xml

    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    # Fetch metadata
    try:
        metadata_xml = fetch_sp_metadata(metadata_url)
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="sp_metadata_fetch_error",
        )

    tenant_id = requesting_user["tenant_id"]

    # Parse metadata
    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="sp_metadata_parse_error",
        )

    # Check for duplicate entity_id
    existing = database.service_providers.get_service_provider_by_entity_id(
        tenant_id, parsed["entity_id"]
    )
    if existing:
        raise ConflictError(
            message=f"A service provider with entity ID '{parsed['entity_id']}' already exists",
            code="sp_entity_id_exists",
        )

    row = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        entity_id=parsed["entity_id"],
        acs_url=parsed["acs_url"],
        certificate_pem=parsed.get("certificate_pem"),
        nameid_format=parsed.get(
            "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        metadata_xml=metadata_xml,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to create service provider",
            code="sp_creation_failed",
        )

    sp_id = str(row["id"])

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_created",
        metadata={
            "name": name,
            "entity_id": parsed["entity_id"],
            "method": "metadata_url",
            "metadata_url": metadata_url,
        },
    )

    # Eagerly generate per-SP signing certificate
    _get_or_create_sp_signing_certificate(tenant_id, sp_id, requesting_user["id"])

    return _row_to_config(row)


def delete_service_provider(
    requesting_user: RequestingUser,
    sp_id: str,
) -> None:
    """Delete an SP.

    Authorization: Requires super_admin role.
    Logs: service_provider_deleted event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists and get name for event log
    existing = database.service_providers.get_service_provider(tenant_id, sp_id)
    if existing is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    database.service_providers.delete_service_provider(tenant_id, sp_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_deleted",
        metadata={"name": existing["name"]},
    )


# ============================================================================
# SP Lookup (SSO flow - no auth required, tenant-scoped via RLS)
# ============================================================================


def get_sp_by_entity_id(tenant_id: str, entity_id: str) -> SPConfig | None:
    """Look up an SP by entity ID. No auth check required.

    Used by the SSO endpoint to find the SP that sent the AuthnRequest.
    Tenant scoping is enforced by RLS at the database layer.
    """
    row = database.service_providers.get_service_provider_by_entity_id(tenant_id, entity_id)
    if row is None:
        return None
    return _row_to_config(row)


def build_sso_response(
    tenant_id: str,
    user_id: str,
    sp_entity_id: str,
    authn_request_id: str | None,
    base_url: str,
) -> tuple[str, str]:
    """Build a signed SAML Response for an SSO assertion.

    Args:
        tenant_id: Tenant ID
        user_id: Authenticated user's ID
        sp_entity_id: Entity ID of the requesting SP
        authn_request_id: ID from the AuthnRequest (for InResponseTo)
        base_url: Base URL for building entity ID

    Returns:
        Tuple of (base64_encoded_response, acs_url)

    Raises:
        NotFoundError: If SP or signing certificate not found
        ValidationError: If user data is missing
    """
    from utils.saml import decrypt_private_key
    from utils.saml_assertion import build_saml_response

    # 1. Look up SP
    sp_row = database.service_providers.get_service_provider_by_entity_id(tenant_id, sp_entity_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # 2. Get signing certificate (per-SP first, then tenant fallback)
    sp_id = str(sp_row["id"])
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        cert = database.saml.get_sp_certificate(tenant_id)
    if cert is None:
        raise NotFoundError(
            message="IdP signing certificate not configured",
            code="idp_certificate_not_found",
        )

    # 3. Decrypt private key
    private_key_pem = decrypt_private_key(cert["private_key_pem_enc"])

    # 4. Get user info
    user = database.users.get_user_by_id(tenant_id, user_id)
    if user is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    primary_email_row = database.user_emails.get_primary_email(tenant_id, user_id)
    if primary_email_row is None:
        raise ValidationError(
            message="User has no primary email",
            code="user_no_email",
        )

    email = primary_email_row["email"]

    # 5. Build user attributes
    user_attributes = {
        "email": email,
        "firstName": user.get("first_name", ""),
        "lastName": user.get("last_name", ""),
    }

    # 6. Build SAML Response
    issuer_entity_id = f"{base_url}/saml/idp/metadata"
    name_id_format = sp_row.get(
        "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )

    saml_response_b64 = build_saml_response(
        issuer_entity_id=issuer_entity_id,
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_row["acs_url"],
        name_id=email,
        name_id_format=name_id_format,
        authn_request_id=authn_request_id,
        user_attributes=user_attributes,
        certificate_pem=cert["certificate_pem"],
        private_key_pem=private_key_pem,
    )

    # 7. Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="service_provider",
        artifact_id=str(sp_row["id"]),
        event_type="sso_assertion_issued",
        metadata={
            "sp_entity_id": sp_entity_id,
            "sp_name": sp_row["name"],
        },
    )

    return saml_response_b64, sp_row["acs_url"]


# ============================================================================
# IdP Metadata
# ============================================================================


def get_tenant_idp_metadata_xml(tenant_id: str, base_url: str) -> str:
    """Generate IdP metadata XML for downstream SPs to consume.

    No authorization required (public endpoint).

    Args:
        tenant_id: Tenant ID
        base_url: Base URL for the tenant

    Returns:
        XML metadata string

    Raises:
        NotFoundError: If no SP certificate is configured for the tenant
    """
    cert = database.saml.get_sp_certificate(tenant_id)

    if cert is None:
        raise NotFoundError(
            message="IdP certificate not configured",
            code="idp_certificate_not_found",
        )

    entity_id = f"{base_url}/saml/idp/metadata"
    sso_url = f"{base_url}/saml/idp/sso"

    return generate_idp_metadata_xml(
        entity_id=entity_id,
        sso_url=sso_url,
        certificate_pem=cert["certificate_pem"],
    )


def get_sp_idp_metadata_xml(tenant_id: str, sp_id: str, base_url: str) -> str:
    """Generate IdP metadata XML with per-SP signing certificate.

    No authorization required (public endpoint).
    Falls back to tenant cert if no per-SP cert exists.

    Args:
        tenant_id: Tenant ID
        sp_id: Service Provider ID
        base_url: Base URL for the tenant

    Returns:
        XML metadata string

    Raises:
        NotFoundError: If SP not found or no certificate available
    """
    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # Try per-SP cert first, then tenant cert
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        cert = database.saml.get_sp_certificate(tenant_id)
    if cert is None:
        raise NotFoundError(
            message="IdP certificate not configured",
            code="idp_certificate_not_found",
        )

    entity_id = f"{base_url}/saml/idp/metadata"
    sso_url = f"{base_url}/saml/idp/sso"

    return generate_idp_metadata_xml(
        entity_id=entity_id,
        sso_url=sso_url,
        certificate_pem=cert["certificate_pem"],
    )


# ============================================================================
# Per-SP Signing Certificate Management
# ============================================================================


def get_sp_signing_certificate(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPSigningCertificate:
    """Get signing certificate info for an SP.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        raise NotFoundError(
            message="Signing certificate not found for this service provider",
            code="sp_signing_certificate_not_found",
        )

    return SPSigningCertificate(
        id=str(cert["id"]),
        sp_id=str(cert["sp_id"]),
        certificate_pem=cert["certificate_pem"],
        expires_at=cert["expires_at"],
        created_at=cert["created_at"],
        has_previous_certificate=cert["previous_certificate_pem"] is not None,
        rotation_grace_period_ends_at=cert.get("rotation_grace_period_ends_at"),
    )


def rotate_sp_signing_certificate(
    requesting_user: RequestingUser,
    sp_id: str,
    grace_period_days: int = 7,
) -> SPSigningCertificateRotationResult:
    """Rotate the signing certificate for an SP.

    Authorization: Requires super_admin role.
    Logs: sp_signing_certificate_rotated event.
    """
    from datetime import UTC, datetime, timedelta

    from utils.saml import encrypt_private_key, generate_sp_certificate, get_certificate_expiry

    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # Get current certificate
    current = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if current is None:
        raise NotFoundError(
            message="No signing certificate exists to rotate",
            code="sp_signing_certificate_not_found",
        )

    # Generate new certificate
    new_cert_pem, new_key_pem = generate_sp_certificate(tenant_id)
    new_encrypted_key = encrypt_private_key(new_key_pem)
    new_expires_at = get_certificate_expiry(new_cert_pem)

    # Calculate grace period end
    grace_period_ends = datetime.now(UTC) + timedelta(days=grace_period_days)

    # Rotate
    result = database.sp_signing_certificates.rotate_signing_certificate(
        tenant_id=tenant_id,
        sp_id=sp_id,
        new_certificate_pem=new_cert_pem,
        new_private_key_pem_enc=new_encrypted_key,
        new_expires_at=new_expires_at,
        previous_certificate_pem=current["certificate_pem"],
        previous_private_key_pem_enc=current["private_key_pem_enc"],
        previous_expires_at=current["expires_at"],
        rotation_grace_period_ends_at=grace_period_ends,
    )

    if result is None:
        raise ValidationError(
            message="Failed to rotate SP signing certificate",
            code="sp_signing_certificate_rotation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="sp_signing_certificate",
        artifact_id=str(result["id"]),
        event_type="sp_signing_certificate_rotated",
        metadata={
            "sp_id": sp_id,
            "grace_period_days": grace_period_days,
            "grace_period_ends_at": str(grace_period_ends),
            "new_expires_at": str(new_expires_at),
        },
    )

    return SPSigningCertificateRotationResult(
        new_certificate_pem=new_cert_pem,
        new_expires_at=new_expires_at,
        grace_period_ends_at=grace_period_ends,
    )


def get_sp_metadata_url_info(
    requesting_user: RequestingUser,
    sp_id: str,
    base_url: str,
) -> SPMetadataURLInfo:
    """Get per-SP metadata URL info.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    return SPMetadataURLInfo(
        metadata_url=f"{base_url}/saml/idp/metadata/{sp_id}",
        entity_id=f"{base_url}/saml/idp/metadata",
        sso_url=f"{base_url}/saml/idp/sso",
        sp_id=sp_id,
        sp_name=sp_row["name"],
    )
