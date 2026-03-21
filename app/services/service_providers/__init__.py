"""Downstream SAML Service Provider management.

This package provides business logic for SP management:
- SP CRUD operations (create, read, list, delete, import)
- SSO flow lookups and response building
- IdP metadata generation
- Per-SP signing certificate management
- Group assignments and user access checks

All functions:
- Receive a RequestingUser for authorization (where applicable)
- Return Pydantic models from app/schemas/service_providers.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads

This module re-exports all public functions for backwards compatibility.
Existing code using `from services import service_providers` will continue to work.
"""

# Re-export converters for backwards compatibility
from services.service_providers._converters import (
    _row_to_config,
    _row_to_list_item,
)

# Re-export from crud module
from services.service_providers.crud import (
    create_service_provider,
    delete_service_provider,
    disable_service_provider,
    enable_service_provider,
    get_service_provider,
    import_sp_from_metadata_url,
    import_sp_from_metadata_xml,
    list_service_providers,
    update_service_provider,
)

# Re-export from group_assignments module
from services.service_providers.group_assignments import (
    assign_sp_to_group,
    bulk_assign_sp_to_groups,
    check_user_sp_access,
    count_sp_group_assignments,
    get_user_accessible_apps,
    get_user_accessible_apps_admin,
    list_available_groups_for_sp,
    list_available_sps_for_group,
    list_group_sp_assignments,
    list_sp_group_assignments,
    remove_sp_group_assignment,
)

# Re-export from metadata module
from services.service_providers.metadata import (
    get_sp_idp_metadata_xml,
)

# Re-export from metadata_sync module
from services.service_providers.metadata_sync import (
    apply_sp_metadata_refresh,
    apply_sp_metadata_reimport,
    preview_sp_metadata_refresh,
    preview_sp_metadata_reimport,
)

# Re-export from signing_certs module
from services.service_providers.signing_certs import (
    get_sp_metadata_url_info,
    get_sp_signing_certificate,
    rotate_sp_signing_certificate,
)

# Re-export from slo module
from services.service_providers.slo import (
    process_sp_logout_request,
    propagate_logout_to_sps,
)

# Re-export from sso module
from services.service_providers.sso import (
    build_sso_response,
    get_groups_for_consent,
    get_service_provider_by_id,
    get_sp_by_entity_id,
    get_user_consent_info,
)

# Re-export from trust module
from services.service_providers.trust import (
    establish_trust_from_metadata_url,
    establish_trust_from_metadata_xml,
    establish_trust_manually,
)

__all__ = [
    # CRUD
    "apply_sp_metadata_refresh",
    "apply_sp_metadata_reimport",
    "create_service_provider",
    "delete_service_provider",
    "disable_service_provider",
    "enable_service_provider",
    "establish_trust_from_metadata_url",
    "establish_trust_from_metadata_xml",
    "establish_trust_manually",
    "get_service_provider",
    "import_sp_from_metadata_url",
    "import_sp_from_metadata_xml",
    "list_service_providers",
    "preview_sp_metadata_refresh",
    "preview_sp_metadata_reimport",
    "update_service_provider",
    # SLO
    "process_sp_logout_request",
    "propagate_logout_to_sps",
    # SSO
    "build_sso_response",
    "get_groups_for_consent",
    "get_service_provider_by_id",
    "get_sp_by_entity_id",
    "get_user_consent_info",
    # Metadata
    "get_sp_idp_metadata_xml",
    # Signing certificates
    "get_sp_metadata_url_info",
    "get_sp_signing_certificate",
    "rotate_sp_signing_certificate",
    # Group assignments
    "assign_sp_to_group",
    "bulk_assign_sp_to_groups",
    "check_user_sp_access",
    "count_sp_group_assignments",
    "get_user_accessible_apps",
    "get_user_accessible_apps_admin",
    "list_available_groups_for_sp",
    "list_available_sps_for_group",
    "list_group_sp_assignments",
    "list_sp_group_assignments",
    "remove_sp_group_assignment",
    # Private (for backwards compatibility)
    "_row_to_config",
    "_row_to_list_item",
]
