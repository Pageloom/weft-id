"""SP CRUD operations.

Create, read, update, delete operations for downstream service providers,
including import from metadata XML/URL.
"""

import logging

import database
from schemas.service_providers import SPConfig, SPCreate, SPListResponse, SPUpdate
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.service_providers._converters import _row_to_config, _row_to_list_item
from services.types import RequestingUser

logger = logging.getLogger(__name__)


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


def _create_sp_from_parsed_metadata(
    tenant_id: str,
    requesting_user: RequestingUser,
    name: str,
    parsed: dict,
    metadata_xml: str,
    method: str,
    extra_metadata: dict | None = None,
) -> SPConfig:
    """Create an SP from parsed metadata (shared by XML and URL import).

    Handles entity_id duplicate check, DB insert, event logging,
    and signing certificate generation.
    """
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

    event_metadata = {
        "name": name,
        "entity_id": parsed["entity_id"],
        "method": method,
    }
    if extra_metadata:
        event_metadata.update(extra_metadata)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_created",
        metadata=event_metadata,
    )

    # Eagerly generate per-SP signing certificate
    _get_or_create_sp_signing_certificate(tenant_id, sp_id, requesting_user["id"])

    return _row_to_config(row)


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

    # Batch-fetch assignment counts for all SPs
    assignment_counts = database.sp_group_assignments.count_assignments_for_sps(tenant_id)

    # Enrich each SP with signing cert expiry and assignment count
    items = []
    for row in rows:
        sp_id = str(row["id"])
        cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
        cert_expires = cert["expires_at"] if cert else None
        items.append(
            _row_to_list_item(
                row,
                signing_cert_expires_at=cert_expires,
                assigned_group_count=assignment_counts.get(sp_id, 0),
            )
        )

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
        description=data.description,
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

    # Parse metadata
    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="sp_metadata_parse_error",
        )

    return _create_sp_from_parsed_metadata(
        tenant_id=requesting_user["tenant_id"],
        requesting_user=requesting_user,
        name=name,
        parsed=parsed,
        metadata_xml=metadata_xml,
        method="metadata_xml",
    )


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

    # Parse metadata
    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="sp_metadata_parse_error",
        )

    return _create_sp_from_parsed_metadata(
        tenant_id=requesting_user["tenant_id"],
        requesting_user=requesting_user,
        name=name,
        parsed=parsed,
        metadata_xml=metadata_xml,
        method="metadata_url",
        extra_metadata={"metadata_url": metadata_url},
    )


def update_service_provider(
    requesting_user: RequestingUser,
    sp_id: str,
    data: SPUpdate,
) -> SPConfig:
    """Update an SP's mutable configuration fields.

    Authorization: Requires super_admin role.
    Logs: service_provider_updated event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    existing = database.service_providers.get_service_provider(tenant_id, sp_id)
    if existing is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # Build update kwargs from provided (non-None) fields
    update_fields: dict = {}
    if data.name is not None:
        update_fields["name"] = data.name
    if data.description is not None:
        update_fields["description"] = data.description
    if data.acs_url is not None:
        update_fields["acs_url"] = data.acs_url

    if not update_fields:
        raise ValidationError(
            message="At least one field must be provided for update",
            code="sp_update_no_fields",
        )

    row = database.service_providers.update_service_provider(tenant_id, sp_id, **update_fields)

    if row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_updated",
        metadata={"changed_fields": list(update_fields.keys())},
    )

    config = _row_to_config(row)

    # Enrich with signing cert expiry
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]

    return config


def enable_service_provider(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPConfig:
    """Enable a disabled SP.

    Authorization: Requires super_admin role.
    Logs: service_provider_enabled event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    existing = database.service_providers.get_service_provider(tenant_id, sp_id)
    if existing is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    if existing.get("enabled", True):
        raise ValidationError(
            message="Service provider is already enabled",
            code="sp_already_enabled",
        )

    row = database.service_providers.set_service_provider_enabled(tenant_id, sp_id, True)

    if row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_enabled",
        metadata={"name": row["name"]},
    )

    config = _row_to_config(row)
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]

    return config


def disable_service_provider(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPConfig:
    """Disable an enabled SP. Disabled SPs reject SSO requests.

    Authorization: Requires super_admin role.
    Logs: service_provider_disabled event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    existing = database.service_providers.get_service_provider(tenant_id, sp_id)
    if existing is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    if not existing.get("enabled", True):
        raise ValidationError(
            message="Service provider is already disabled",
            code="sp_already_disabled",
        )

    row = database.service_providers.set_service_provider_enabled(tenant_id, sp_id, False)

    if row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_disabled",
        metadata={"name": row["name"]},
    )

    config = _row_to_config(row)
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]

    return config


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
