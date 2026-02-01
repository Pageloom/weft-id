"""SAML service layer.

This package provides business logic for SAML SSO operations:
- IdP management (CRUD)
- SP certificate management
- SAML request/response processing
- Metadata import and refresh
- Domain binding and user assignment
- Single Logout (SLO)
- Authentication routing

All functions follow the service layer pattern:
- Receive RequestingUser for authorization (except public auth endpoints)
- Return Pydantic schemas
- Raise ServiceError subclasses on failure
- Log events for all writes

This module re-exports all public functions for backwards compatibility.
Existing code using `from services import saml as saml_service` will continue to work.
"""

# Re-export from auth module
# Re-export private converters for backwards compatibility
from services.saml._converters import (
    idp_row_to_config as _idp_row_to_config,
)
from services.saml._converters import (
    idp_row_to_list_item as _idp_row_to_list_item,
)

# Re-export private helpers for backwards compatibility
# Some tests directly import these
from services.saml._helpers import (
    get_saml_attribute as _get_saml_attribute,
)
from services.saml._helpers import (
    get_saml_group_attributes as _get_saml_group_attributes,
)
from services.saml.auth import (
    build_authn_request,
    get_default_idp,
    get_enabled_idps_for_login,
    get_idp_by_issuer,
    get_idp_for_saml_login,
    process_saml_response,
    process_saml_test_response,
)

# Re-export from certificates module
from services.saml.certificates import (
    get_or_create_sp_certificate,
    get_sp_metadata,
    get_tenant_sp_metadata_xml,
    rotate_sp_certificate,
)

# Re-export from debug module
from services.saml.debug import (
    get_saml_debug_entry,
    list_saml_debug_entries,
    store_saml_debug_entry,
)

# Re-export from domains module
from services.saml.domains import (
    assign_user_idp,
    bind_domain_to_idp,
    get_unbound_domains,
    list_domain_bindings,
    rebind_domain_to_idp,
    unbind_domain_from_idp,
)

# Re-export from logout module
from services.saml.logout import (
    initiate_sp_logout,
    process_idp_logout_request,
)

# Re-export from metadata module
from services.saml.metadata import (
    fetch_and_parse_idp_metadata,
    import_idp_from_metadata_url,
    import_idp_from_metadata_xml,
    parse_idp_metadata_xml_to_schema,
    refresh_all_idp_metadata,
    refresh_idp_from_metadata,
)

# Re-export from providers module
from services.saml.providers import (
    create_identity_provider,
    delete_identity_provider,
    get_identity_provider,
    get_provider_presets,
    idp_requires_platform_mfa,
    list_identity_providers,
    set_idp_default,
    set_idp_enabled,
    update_identity_provider,
)

# Re-export from provisioning module
from services.saml.provisioning import (
    authenticate_via_saml,
    jit_provision_user,
)

# Re-export from routing module
from services.saml.routing import (
    determine_auth_route,
)

# Alias the JIT provision function with underscore prefix for backwards compatibility
_jit_provision_user = jit_provision_user

__all__ = [
    # Auth
    "build_authn_request",
    "get_default_idp",
    "get_enabled_idps_for_login",
    "get_idp_by_issuer",
    "get_idp_for_saml_login",
    "process_saml_response",
    "process_saml_test_response",
    # Certificates
    "get_or_create_sp_certificate",
    "get_sp_metadata",
    "get_tenant_sp_metadata_xml",
    "rotate_sp_certificate",
    # Debug
    "get_saml_debug_entry",
    "list_saml_debug_entries",
    "store_saml_debug_entry",
    # Domains
    "assign_user_idp",
    "bind_domain_to_idp",
    "get_unbound_domains",
    "list_domain_bindings",
    "rebind_domain_to_idp",
    "unbind_domain_from_idp",
    # Logout
    "initiate_sp_logout",
    "process_idp_logout_request",
    # Metadata
    "fetch_and_parse_idp_metadata",
    "import_idp_from_metadata_url",
    "import_idp_from_metadata_xml",
    "parse_idp_metadata_xml_to_schema",
    "refresh_all_idp_metadata",
    "refresh_idp_from_metadata",
    # Providers
    "create_identity_provider",
    "delete_identity_provider",
    "get_identity_provider",
    "get_provider_presets",
    "idp_requires_platform_mfa",
    "list_identity_providers",
    "set_idp_default",
    "set_idp_enabled",
    "update_identity_provider",
    # Provisioning
    "authenticate_via_saml",
    "jit_provision_user",
    # Routing
    "determine_auth_route",
    # Private helpers (for backwards compatibility)
    "_get_saml_attribute",
    "_get_saml_group_attributes",
    "_idp_row_to_config",
    "_idp_row_to_list_item",
    "_jit_provision_user",
]
