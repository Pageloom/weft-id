"""SAML database operations for SP certificates and identity providers."""

from database.saml.certificates import (
    clear_previous_certificate,
    create_sp_certificate,
    get_sp_certificate,
    rotate_sp_certificate,
    update_sp_certificate,
)
from database.saml.debug import (
    delete_old_debug_entries,
    get_debug_entries,
    get_debug_entry,
    store_debug_entry,
)
from database.saml.domains import (
    bind_domain_to_idp,
    get_domain_binding_by_domain_id,
    get_domain_bindings_for_idp,
    get_idp_for_domain,
    get_unbound_domains,
    list_domains_with_bindings,
    unbind_domain_from_idp,
)
from database.saml.idp_certificates import (
    create_idp_certificate,
    delete_idp_certificate,
    get_idp_certificate,
    get_idp_certificate_by_fingerprint,
    list_idp_certificates,
    update_idp_certificate_fingerprint,
)
from database.saml.idp_sp_certificates import (
    clear_previous_idp_sp_certificate,
    create_idp_sp_certificate,
    get_idp_sp_certificate,
    get_idp_sp_certificates_needing_rotation_or_cleanup,
    rotate_idp_sp_certificate,
)
from database.saml.providers import (
    create_identity_provider,
    delete_identity_provider,
    get_default_identity_provider,
    get_enabled_identity_providers,
    get_identity_provider,
    get_identity_provider_by_entity_id,
    get_idps_with_metadata_url,
    get_public_idp_info,
    get_user_assigned_idp,
    list_identity_providers,
    set_idp_default,
    set_idp_enabled,
    set_idp_metadata_error,
    set_idp_trust_established,
    set_user_idp,
    set_verbose_logging,
    update_identity_provider,
    update_idp_metadata_fields,
)
from database.saml.security import (
    count_domain_bindings_for_idp,
    count_users_with_idp,
    count_users_with_idp_in_domain,
    count_users_without_idp_in_domain,
)

__all__ = [
    # idp_certificates
    "list_idp_certificates",
    "get_idp_certificate",
    "get_idp_certificate_by_fingerprint",
    "create_idp_certificate",
    "delete_idp_certificate",
    "update_idp_certificate_fingerprint",
    # certificates
    "get_sp_certificate",
    "create_sp_certificate",
    "update_sp_certificate",
    "rotate_sp_certificate",
    "clear_previous_certificate",
    # providers
    "list_identity_providers",
    "get_identity_provider",
    "get_identity_provider_by_entity_id",
    "create_identity_provider",
    "update_identity_provider",
    "update_idp_metadata_fields",
    "set_idp_metadata_error",
    "set_idp_enabled",
    "set_idp_default",
    "set_idp_trust_established",
    "delete_identity_provider",
    "get_enabled_identity_providers",
    "get_public_idp_info",
    "get_default_identity_provider",
    "get_user_assigned_idp",
    "set_user_idp",
    "set_verbose_logging",
    "get_idps_with_metadata_url",
    # domains
    "get_domain_bindings_for_idp",
    "get_idp_for_domain",
    "bind_domain_to_idp",
    "unbind_domain_from_idp",
    "get_unbound_domains",
    "list_domains_with_bindings",
    "get_domain_binding_by_domain_id",
    # security
    "count_users_with_idp",
    "count_domain_bindings_for_idp",
    "count_users_without_idp_in_domain",
    "count_users_with_idp_in_domain",
    # idp_sp_certificates
    "get_idp_sp_certificate",
    "get_idp_sp_certificates_needing_rotation_or_cleanup",
    "create_idp_sp_certificate",
    "rotate_idp_sp_certificate",
    "clear_previous_idp_sp_certificate",
    # debug
    "store_debug_entry",
    "get_debug_entries",
    "get_debug_entry",
    "delete_old_debug_entries",
]
