"""Settings service layer.

This package provides business logic for settings operations:
- Privileged domains management (domains.py)
- Tenant security settings (security.py)

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/settings.py
- Raise ServiceError subclasses on failures
- Have no knowledge of HTTP concepts
"""

from services.settings.domains import (
    add_domain_group_link,
    add_privileged_domain,
    auto_assign_user_to_domain_groups,
    delete_domain_group_link,
    delete_privileged_domain,
    get_privileged_domains_list,
    is_privileged_domain,
    list_domain_group_links,
    list_privileged_domains,
)
from services.settings.security import (
    can_user_edit_profile,
    get_certificate_lifetime,
    get_certificate_rotation_window,
    get_group_assertion_scope,
    get_inactivity_threshold,
    get_password_policy,
    get_required_auth_strength,
    get_security_settings,
    get_session_settings,
    requires_email_verification_for_login,
    update_security_settings,
)

__all__ = [
    # Domains
    "add_domain_group_link",
    "add_privileged_domain",
    "auto_assign_user_to_domain_groups",
    "delete_domain_group_link",
    "delete_privileged_domain",
    "get_privileged_domains_list",
    "is_privileged_domain",
    "list_domain_group_links",
    "list_privileged_domains",
    # Security
    "can_user_edit_profile",
    "get_certificate_lifetime",
    "get_certificate_rotation_window",
    "get_group_assertion_scope",
    "get_inactivity_threshold",
    "get_password_policy",
    "get_required_auth_strength",
    "get_security_settings",
    "get_session_settings",
    "requires_email_verification_for_login",
    "update_security_settings",
]
