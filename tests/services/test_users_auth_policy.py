"""Tests for services.users.auth_policy.user_must_enroll_enhanced."""

from schemas.settings import TenantSecuritySettingsUpdate
from services import settings as settings_service
from services import users as users_service


def _make_requesting_user(user: dict, tenant_id: str, role: str | None = None) -> dict:
    return {
        "id": str(user["id"]),
        "tenant_id": tenant_id,
        "role": role or user["role"],
    }


def _set_policy(tenant_id: str, super_admin: dict, value: str) -> None:
    requesting_user = _make_requesting_user(super_admin, tenant_id, "super_admin")
    settings_service.update_security_settings(
        requesting_user, TenantSecuritySettingsUpdate(required_auth_strength=value)
    )


def test_user_must_enroll_enhanced_false_under_baseline(test_tenant, test_super_admin_user):
    """Under baseline policy, no user needs to enroll regardless of mfa_method."""
    # Default policy is baseline; explicitly set to make the test intent clear
    _set_policy(test_tenant["id"], test_super_admin_user, "baseline")

    assert (
        users_service.user_must_enroll_enhanced(test_tenant["id"], {"mfa_method": "email"}) is False
    )
    assert (
        users_service.user_must_enroll_enhanced(test_tenant["id"], {"mfa_method": "totp"}) is False
    )
    assert users_service.user_must_enroll_enhanced(test_tenant["id"], {}) is False


def test_user_must_enroll_enhanced_true_for_email_method_under_enhanced(
    test_tenant, test_super_admin_user
):
    """Under enhanced policy, a user with mfa_method='email' must enroll."""
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")

    assert (
        users_service.user_must_enroll_enhanced(test_tenant["id"], {"mfa_method": "email"}) is True
    )


def test_user_must_enroll_enhanced_false_for_totp_method_under_enhanced(
    test_tenant, test_super_admin_user
):
    """Under enhanced policy, a TOTP user does not need to enroll."""
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")

    assert (
        users_service.user_must_enroll_enhanced(test_tenant["id"], {"mfa_method": "totp"}) is False
    )


def test_user_must_enroll_enhanced_true_for_missing_mfa_method_under_enhanced(
    test_tenant, test_super_admin_user
):
    """Under enhanced policy, a user record without mfa_method defaults to needing enrollment."""
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")

    # No mfa_method set at all
    assert users_service.user_must_enroll_enhanced(test_tenant["id"], {}) is True
