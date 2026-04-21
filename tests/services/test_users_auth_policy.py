"""Tests for services.users.auth_policy.user_must_enroll_enhanced."""

import database
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


def _cred_bytes(seed: int) -> bytes:
    """Deterministic credential_id bytes for tests."""
    return (b"\x00" * 16 + seed.to_bytes(16, "big"))[-32:]


def _create_passkey(tenant_id: str, user_id: str, seed: int = 1) -> dict:
    return database.webauthn_credentials.create_credential(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        user_id=str(user_id),
        credential_id=_cred_bytes(seed),
        public_key=b"pk-bytes",
        name=f"Test passkey {seed}",
        sign_count=0,
        aaguid=None,
        transports=None,
        backup_eligible=False,
        backup_state=False,
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


def test_user_must_enroll_enhanced_false_when_user_has_passkey(
    test_tenant, test_super_admin_user, test_user
):
    """Under enhanced policy, a registered passkey satisfies the policy even
    when ``mfa_method`` is still ``email`` (profile/registration check with
    no login context).
    """
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")
    _create_passkey(test_tenant["id"], test_user["id"], seed=1)

    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "email"},
        )
        is False
    )


def test_email_otp_never_satisfies_enhanced_even_with_passkeys(
    test_tenant, test_super_admin_user, test_user
):
    """Under enhanced policy, email OTP at login time always requires
    enrollment, even when the user has registered passkeys.
    """
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")
    _create_passkey(test_tenant["id"], test_user["id"], seed=20)

    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "email"},
            login_mfa_method="email",
        )
        is True
    )


def test_backup_code_satisfies_enhanced_when_user_has_passkey(
    test_tenant, test_super_admin_user, test_user
):
    """Backup codes are a legitimate recovery mechanism. A passkey user who
    uses a backup code at login has already enrolled in a strong method.
    """
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")
    _create_passkey(test_tenant["id"], test_user["id"], seed=21)

    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "email"},
            login_mfa_method="backup_code",
        )
        is False
    )


def test_totp_login_satisfies_enhanced(test_tenant, test_super_admin_user, test_user):
    """TOTP at login time satisfies enhanced policy."""
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")

    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "totp"},
            login_mfa_method="totp",
        )
        is False
    )


def test_user_must_enroll_enhanced_true_when_no_passkey_and_email_only(
    test_tenant, test_super_admin_user, test_user
):
    """Under enhanced policy with no passkey and email-only MFA, enrollment is required."""
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")

    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "email"},
        )
        is True
    )


def test_user_must_enroll_enhanced_under_baseline_with_passkey_still_false(
    test_tenant, test_super_admin_user, test_user
):
    """Passkeys never trigger enrollment under baseline -- the gate short-circuits."""
    _set_policy(test_tenant["id"], test_super_admin_user, "baseline")
    _create_passkey(test_tenant["id"], test_user["id"], seed=1)

    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "email"},
        )
        is False
    )


def test_passkey_in_one_tenant_does_not_satisfy_enhanced_in_another(
    test_tenant, test_super_admin_user, test_user, mocker
):
    """A passkey in tenant B must not satisfy enhanced policy in tenant A."""
    # Create a different tenant id to simulate the cross-tenant lookup.
    other_tenant_id = "11111111-1111-1111-1111-111111111111"
    # Enhanced in "other" tenant; passkey lives in test_tenant.
    mocker.patch(
        "database.security.get_required_auth_strength",
        return_value="enhanced",
    )
    # Mock count_credentials so we see it is called with the *other* tenant id
    # and returns 0 there (i.e., the passkey in ``test_tenant`` is isolated).
    mock_count = mocker.patch(
        "database.webauthn_credentials.count_credentials",
        return_value=0,
    )
    _create_passkey(test_tenant["id"], test_user["id"], seed=5)

    result = users_service.user_must_enroll_enhanced(
        other_tenant_id,
        {"id": test_user["id"], "mfa_method": "email"},
    )

    assert result is True
    # count_credentials must have been asked in the *other* tenant's scope,
    # not in test_tenant's -- this is what enforces isolation.
    assert mock_count.call_args.args[0] == other_tenant_id


def test_tightening_policy_with_mixed_user_population_only_blocks_email_only(
    test_tenant, test_super_admin_user, test_user, test_admin_user
):
    """Tighten policy from baseline to enhanced with a mixed user population.

    Seed three users representing the three auth postures:
      A = email only, no passkey  (must enroll)
      B = TOTP                    (satisfied)
      C = email only, 1 passkey   (satisfied)

    Only user A should be funneled into enrollment after the policy tightens.
    """
    # Start at baseline.
    _set_policy(test_tenant["id"], test_super_admin_user, "baseline")

    # test_user is our "email only, no passkey" user (A). Defaults to mfa_method=email.
    # test_admin_user will play the role of "TOTP user" (B) via stubbed dict below.
    # test_super_admin_user will play the role of "email + passkey" user (C).
    _create_passkey(test_tenant["id"], test_super_admin_user["id"], seed=9)

    # Tighten.
    _set_policy(test_tenant["id"], test_super_admin_user, "enhanced")

    # A: email only, no passkey -> must enroll.
    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_user["id"], "mfa_method": "email"},
        )
        is True
    )
    # B: TOTP -> satisfied.
    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_admin_user["id"], "mfa_method": "totp"},
        )
        is False
    )
    # C: email + registered passkey -> satisfied.
    assert (
        users_service.user_must_enroll_enhanced(
            test_tenant["id"],
            {"id": test_super_admin_user["id"], "mfa_method": "email"},
        )
        is False
    )
