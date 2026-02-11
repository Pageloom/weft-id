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
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.types import RequestingUser

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


def _row_to_list_item(row: dict) -> SPListItem:
    """Convert database row to SPListItem schema."""
    return SPListItem(
        id=str(row["id"]),
        name=row["name"],
        entity_id=row["entity_id"],
        created_at=row["created_at"],
    )


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

    rows = database.service_providers.list_service_providers(requesting_user["tenant_id"])
    items = [_row_to_list_item(row) for row in rows]

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

    row = database.service_providers.get_service_provider(requesting_user["tenant_id"], sp_id)

    if row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    return _row_to_config(row)


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
