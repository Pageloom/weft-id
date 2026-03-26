"""User service layer.

This package provides business logic for user operations:
- User CRUD (list, get, create, update, delete)
- Current user profile management
- User lifecycle state (inactivation, reactivation, anonymization)

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/api.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads

This module re-exports all public functions for backwards compatibility.
Existing code using `from services import users` will continue to work.
"""

# Re-export converters for backwards compatibility
from services.users._converters import (
    _fetch_user_detail,
    _user_row_to_detail,
    _user_row_to_profile,
    _user_row_to_summary,
)

# Re-export validation helpers for backwards compatibility
from services.users._validation import _validate_role_change

# Re-export from crud module
from services.users.crud import (
    create_user,
    delete_user,
    get_user,
    list_users,
    resend_invitation,
    update_user,
)

# Re-export from password module
from services.users.password import (
    change_password,
    complete_forced_password_reset,
    complete_self_service_password_reset,
    force_password_reset,
    request_password_reset,
    validate_reset_token,
)

# Re-export from profile module
from services.users.profile import (
    get_current_user_profile,
    update_current_user_profile,
)

# Re-export from state module
from services.users.state import (
    anonymize_user,
    inactivate_user,
    reactivate_user,
    self_reactivate_super_admin,
)

# Re-export from utilities module
from services.users.utilities import (
    add_unverified_email_with_nonce,
    add_verified_email_with_nonce,
    check_collation_exists,
    count_users,
    create_user_raw,
    email_exists,
    get_admin_emails,
    get_auth_method_options,
    get_available_roles,
    get_tenant_name,
    get_user_by_id_raw,
    get_user_id_by_email,
    list_users_raw,
    update_last_login,
    update_locale_and_last_login,
    update_password,
    update_timezone_and_last_login,
    update_timezone_locale_and_last_login,
)

__all__ = [
    # CRUD
    "create_user",
    "delete_user",
    "get_user",
    "list_users",
    "resend_invitation",
    "update_user",
    # Password
    "change_password",
    "complete_forced_password_reset",
    "complete_self_service_password_reset",
    "force_password_reset",
    "request_password_reset",
    "validate_reset_token",
    # Profile
    "get_current_user_profile",
    "update_current_user_profile",
    # State
    "anonymize_user",
    "inactivate_user",
    "reactivate_user",
    "self_reactivate_super_admin",
    # Utilities
    "add_unverified_email_with_nonce",
    "add_verified_email_with_nonce",
    "check_collation_exists",
    "count_users",
    "create_user_raw",
    "email_exists",
    "get_admin_emails",
    "get_auth_method_options",
    "get_available_roles",
    "get_tenant_name",
    "get_user_by_id_raw",
    "get_user_id_by_email",
    "list_users_raw",
    "update_last_login",
    "update_locale_and_last_login",
    "update_password",
    "update_timezone_and_last_login",
    "update_timezone_locale_and_last_login",
    # Private (for backwards compatibility)
    "_fetch_user_detail",
    "_user_row_to_detail",
    "_user_row_to_profile",
    "_user_row_to_summary",
    "_validate_role_change",
]
