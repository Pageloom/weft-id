"""Identity Provider (IdP) CRUD operations.

This module handles management of SAML Identity Providers:
- List, get, create, update, delete IdPs
- Enable/disable IdPs
- Set default IdP
- Provider presets for common IdPs (Okta, Azure AD, Google)
"""

import logging
from typing import Any

import database
import services.groups as groups_service
from schemas.saml import (
    PROVIDER_ATTRIBUTE_PRESETS,
    PROVIDER_SETUP_GUIDES,
    IdPConfig,
    IdPCreate,
    IdPListResponse,
    IdPUpdate,
    ProviderPresets,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.saml._converters import idp_row_to_config, idp_row_to_list_item
from services.types import RequestingUser
from utils.saml import make_sp_entity_id

logger = logging.getLogger(__name__)


# ============================================================================
# Provider Presets
# ============================================================================


def get_provider_presets(provider_type: str) -> ProviderPresets | None:
    """
    Get provider-specific attribute mapping presets and setup guide.

    This is a public function that doesn't require authentication.
    It helps users configure IdPs by providing known-good attribute mappings
    for common providers (Okta, Azure AD, Google).

    Args:
        provider_type: One of 'okta', 'azure_ad', 'google', 'generic'

    Returns:
        ProviderPresets with attribute_mapping and setup_guide_url,
        or None if provider_type is not recognized.
    """
    if provider_type not in PROVIDER_ATTRIBUTE_PRESETS:
        return None

    return ProviderPresets(
        provider_type=provider_type,
        attribute_mapping=PROVIDER_ATTRIBUTE_PRESETS[provider_type],
        setup_guide_url=PROVIDER_SETUP_GUIDES.get(provider_type),
    )


# ============================================================================
# IdP CRUD Operations
# ============================================================================


def list_identity_providers(
    requesting_user: RequestingUser,
) -> IdPListResponse:
    """
    List all IdPs for the tenant.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.saml.list_identity_providers(requesting_user["tenant_id"])
    items = [idp_row_to_list_item(row) for row in rows]

    return IdPListResponse(items=items, total=len(items))


def get_identity_provider(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Get a single IdP configuration.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    row = database.saml.get_identity_provider(requesting_user["tenant_id"], idp_id)

    if row is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    return idp_row_to_config(row)


def idp_requires_platform_mfa(tenant_id: str, idp_id: str) -> bool:
    """Check if an IdP requires platform MFA after SAML authentication.

    Internal helper for admin-gated routes. No authorization check
    because this only returns a single boolean flag.
    """
    row = database.saml.get_identity_provider(tenant_id, idp_id)
    if row is None:
        return False
    return bool(row.get("require_platform_mfa", False))


def create_identity_provider(
    requesting_user: RequestingUser,
    data: IdPCreate,
    base_url: str,
) -> IdPConfig:
    """
    Create a new IdP configuration.

    Supports two modes:
    - Name-only (two-step): entity_id is None, creates pending IdP with
      per-IdP SP certificate and metadata URL
    - Full creation: entity_id is provided, trust is immediately established

    Authorization: Requires super_admin role.
    Logs: saml_idp_created event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    is_full_creation = data.entity_id is not None

    # Check for duplicate entity_id (only for full creation)
    if is_full_creation and data.entity_id is not None:
        existing = database.saml.get_identity_provider_by_entity_id(tenant_id, data.entity_id)
        if existing:
            raise ConflictError(
                message=f"An IdP with entity ID '{data.entity_id}' already exists",
                code="idp_entity_id_exists",
            )

    # For name-only creation, we'll generate the per-IdP sp_entity_id after getting the ID.
    # Use a placeholder that will be updated after insert (we need the row ID).
    # For full creation, also use per-IdP format.
    # We'll use a temporary sp_entity_id and update it after we know the ID.
    temp_sp_entity_id = f"{base_url}/saml/metadata"

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
        metadata_xml=data.metadata_xml,
        sp_entity_id=temp_sp_entity_id,
        attribute_mapping=data.attribute_mapping,
        is_enabled=data.is_enabled,
        is_default=data.is_default,
        require_platform_mfa=data.require_platform_mfa,
        jit_provisioning=data.jit_provisioning,
        trust_established=is_full_creation,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to create identity provider",
            code="idp_creation_failed",
        )

    idp_id = str(row["id"])

    # Update sp_entity_id to per-IdP format now that we have the ID
    per_idp_sp_entity_id = f"{base_url}/saml/metadata/{idp_id}"
    database.saml.update_identity_provider(tenant_id, idp_id, sp_entity_id=per_idp_sp_entity_id)
    # Refresh the row to get the updated sp_entity_id
    row = database.saml.get_identity_provider(tenant_id, idp_id)

    # Generate per-IdP SP certificate
    from services.saml.idp_sp_certificates import get_or_create_idp_sp_certificate

    get_or_create_idp_sp_certificate(tenant_id, idp_id, requesting_user["id"])

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_created",
        metadata={
            "name": data.name,
            "provider_type": data.provider_type,
            "entity_id": data.entity_id,
            "trust_established": is_full_creation,
        },
    )

    # Create base IdP group
    try:
        groups_service.create_idp_base_group(
            tenant_id=tenant_id,
            idp_id=idp_id,
            idp_name=data.name,
        )
    except ConflictError:
        logger.warning(
            "Could not create base group for IdP %s: group name '%s' already exists",
            idp_id,
            data.name,
        )

    if row is None:
        raise ValidationError(
            message="Failed to create identity provider",
            code="idp_creation_failed",
        )

    return idp_row_to_config(row)


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
    require_super_admin(requesting_user)
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
        return idp_row_to_config(existing)

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
    )

    return idp_row_to_config(row)


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
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists and get name for event log
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Safety check: Block deletion of enabled IdPs
    if existing.get("is_enabled"):
        raise ConflictError(
            message="Cannot delete an enabled identity provider. Disable it first.",
            code="idp_is_enabled",
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

    # Invalidate all IdP groups before deletion (Phase 2: IdP Group Integration)
    # Groups are preserved but marked invalid for historical reference
    invalidated_count = groups_service.invalidate_idp_groups(
        tenant_id=tenant_id,
        idp_id=idp_id,
        idp_name=existing["name"],
    )
    if invalidated_count > 0:
        logger.info(
            "Invalidated %d IdP group(s) before deleting IdP %s",
            invalidated_count,
            existing["name"],
        )

    database.saml.delete_identity_provider(tenant_id, idp_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_deleted",
        metadata={"name": existing["name"]},
    )


def establish_idp_trust(
    requesting_user: RequestingUser,
    idp_id: str,
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
    metadata_url: str | None = None,
    metadata_xml: str | None = None,
) -> IdPConfig:
    """
    Establish trust on a pending IdP.

    Sets the IdP-side fields (entity_id, sso_url, certificate_pem) and marks
    trust_established=true. This completes the second step of two-step creation.

    Authorization: Requires super_admin role.
    Logs: saml_idp_trust_established event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(message="Identity provider not found", code="idp_not_found")

    row = database.saml.set_idp_trust_established(
        tenant_id=tenant_id,
        idp_id=idp_id,
        entity_id=entity_id,
        sso_url=sso_url,
        certificate_pem=certificate_pem,
        slo_url=slo_url,
        metadata_url=metadata_url,
        metadata_xml=metadata_xml,
    )

    if row is None:
        raise ValidationError(
            message="Failed to establish trust",
            code="trust_establishment_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_trust_established",
        metadata={
            "name": existing["name"],
            "entity_id": entity_id,
        },
    )

    return idp_row_to_config(row)


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
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Cannot enable a pending IdP (trust not established)
    if enabled and not existing.get("trust_established", True):
        raise ValidationError(
            message="Cannot enable IdP before trust is established. Import IdP metadata first.",
            code="idp_trust_pending",
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
    )

    return idp_row_to_config(row)


def get_public_trust_info(tenant_id: str, idp_id: str, base_url: str) -> dict:
    """Get trust configuration info for public display. No auth required."""
    row = database.saml.get_public_idp_info(tenant_id, idp_id)
    if not row:
        raise NotFoundError(message="Identity provider not found", code="idp_not_found")

    sp_entity_id = make_sp_entity_id(tenant_id, idp_id)
    sp_acs_url = f"{base_url}/saml/acs/{idp_id}"
    metadata_url = f"{base_url}/saml/metadata/{idp_id}"

    # Build human-readable attribute mapping with requirement info
    jit_enabled = bool(row.get("jit_provisioning"))
    field_meta = {
        "email": {"label": "Email", "required": True, "note": None},
        "first_name": {
            "label": "First Name",
            "required": jit_enabled,
            "note": "Required for JIT provisioning"
            if jit_enabled
            else "Required if JIT provisioning is enabled",
        },
        "last_name": {
            "label": "Last Name",
            "required": jit_enabled,
            "note": "Required for JIT provisioning"
            if jit_enabled
            else "Required if JIT provisioning is enabled",
        },
        "groups": {"label": "Groups", "required": False, "note": None},
    }
    attribute_mapping = row["attribute_mapping"] or {}
    attribute_display = [
        {
            "field": field_meta[key]["label"],
            "attribute": value,
            "required": field_meta[key]["required"],
            "note": field_meta[key]["note"],
        }
        for key, value in attribute_mapping.items()
        if key in field_meta
    ]

    return {
        "name": row["name"],
        "provider_type": row["provider_type"],
        "sp_entity_id": sp_entity_id,
        "sp_acs_url": sp_acs_url,
        "metadata_url": metadata_url,
        "attribute_mapping": attribute_mapping,
        "attribute_display": attribute_display,
    }


def set_idp_default(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Set an IdP as the default for the tenant.

    Authorization: Requires super_admin role.
    Logs: saml_idp_set_default event.
    """
    require_super_admin(requesting_user)
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
    )

    return idp_row_to_config(row)
