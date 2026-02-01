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
from services.saml.certificates import get_or_create_sp_certificate
from services.types import RequestingUser

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
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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

    Authorization: Requires super_admin role.

    Also ensures SP certificate exists for the tenant.
    Logs: saml_idp_created event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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

    idp_id = str(row["id"])

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
            "is_enabled": data.is_enabled,
        },
    )

    # Create base IdP group (Phase 2: IdP Group Integration)
    # This group will contain all users authenticating via this IdP
    try:
        groups_service.create_idp_base_group(
            tenant_id=tenant_id,
            idp_id=idp_id,
            idp_name=data.name,
        )
    except ConflictError:
        # Group name already exists - this is fine, the IdP was still created
        # The admin can manually manage groups if there's a naming conflict
        logger.warning(
            "Could not create base group for IdP %s: group name '%s' already exists",
            idp_id,
            data.name,
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
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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
    )

    return idp_row_to_config(row)


def set_idp_default(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Set an IdP as the default for the tenant.

    Authorization: Requires super_admin role.
    Logs: saml_idp_set_default event.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
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
