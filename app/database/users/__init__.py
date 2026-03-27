"""User account database operations."""

from database.users._utils import check_collation_exists
from database.users.activity import (
    update_last_login,
    update_locale_and_last_login,
    update_timezone_and_last_login,
    update_timezone_locale_and_last_login,
)
from database.users.authentication import (
    bulk_set_password_reset_required,
    clear_hibp_data,
    count_active_super_admins,
    get_admin_emails,
    get_password_hash,
    get_users_with_hibp_prefix,
    get_users_with_weak_policy,
    set_password_reset_required,
    update_mfa_status,
    update_password,
    update_user_role,
)
from database.users.core import (
    create_user,
    delete_user,
    get_user_by_email,
    get_user_by_email_for_reset,
    get_user_by_email_for_saml,
    get_user_by_email_with_status,
    get_user_by_id,
    get_user_with_saml_info,
    is_service_user,
)
from database.users.lifecycle import (
    anonymize_user,
    clear_reactivation_denied,
    get_idle_users_for_tenant,
    inactivate_user,
    reactivate_user,
    set_reactivation_denied,
)
from database.users.listing import count_users, list_all_users_for_export, list_users
from database.users.profile import (
    update_user_locale,
    update_user_profile,
    update_user_theme,
    update_user_timezone,
    update_user_timezone_and_locale,
)
from database.users.saml_assignment import (
    bulk_assign_users_to_idp,
    bulk_inactivate_users,
    bulk_unverify_emails,
    get_user_auth_info,
    get_users_by_email_domain,
    unverify_user_emails,
    update_user_saml_idp,
    wipe_user_password,
)

__all__ = [
    # core
    "get_user_by_id",
    "get_user_by_email",
    "get_user_by_email_for_reset",
    "get_user_by_email_for_saml",
    "get_user_by_email_with_status",
    "get_user_with_saml_info",
    "create_user",
    "delete_user",
    "is_service_user",
    # profile
    "update_user_profile",
    "update_user_timezone",
    "update_user_locale",
    "update_user_theme",
    "update_user_timezone_and_locale",
    # activity
    "update_last_login",
    "update_timezone_and_last_login",
    "update_locale_and_last_login",
    "update_timezone_locale_and_last_login",
    # lifecycle
    "inactivate_user",
    "reactivate_user",
    "anonymize_user",
    "set_reactivation_denied",
    "clear_reactivation_denied",
    "get_idle_users_for_tenant",
    # listing
    "count_users",
    "list_all_users_for_export",
    "list_users",
    # authentication
    "update_user_role",
    "update_password",
    "get_password_hash",
    "set_password_reset_required",
    "update_mfa_status",
    "count_active_super_admins",
    "get_admin_emails",
    "get_users_with_hibp_prefix",
    "clear_hibp_data",
    "get_users_with_weak_policy",
    "bulk_set_password_reset_required",
    # saml_assignment
    "get_user_auth_info",
    "update_user_saml_idp",
    "wipe_user_password",
    "unverify_user_emails",
    "get_users_by_email_domain",
    "bulk_assign_users_to_idp",
    "bulk_inactivate_users",
    "bulk_unverify_emails",
    # utils
    "check_collation_exists",
]
