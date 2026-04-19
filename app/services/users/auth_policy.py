"""Tenant authentication strength policy enforcement for users.

This module exposes helpers for checking whether a user satisfies the
tenant-wide required auth strength (`baseline` vs `enhanced`) and must
therefore be funneled into enhanced enrollment before reaching the
dashboard.

Policy values:
- `baseline`: email OTP, TOTP, and passkey all satisfy two-step verification.
- `enhanced`: only TOTP or a registered passkey satisfies it.

A user whose tenant is on `enhanced` and whose `mfa_method` is still `email`
AND has no registered passkey must enroll in TOTP or a passkey immediately
after signing in.
"""

import database


def user_must_enroll_enhanced(tenant_id: str, user: dict) -> bool:
    """Return True if this user must enroll in a strong auth method now.

    A TOTP-enabled user satisfies the policy. A user with at least one
    registered passkey also satisfies the policy (even if their MFA method
    is still ``email``) because a passkey is a phishing-resistant factor
    on its own.

    Args:
        tenant_id: The tenant ID (used to look up policy).
        user: User dict including at least ``id`` and ``mfa_method``.

    Returns:
        True if the user needs to enroll before continuing; False otherwise.
    """
    policy = database.security.get_required_auth_strength(tenant_id)
    if policy != "enhanced":
        return False

    if user.get("mfa_method") == "totp":
        return False

    user_id = user.get("id")
    if user_id is None:
        return True

    passkey_count = database.webauthn_credentials.count_credentials(tenant_id, str(user_id))
    return passkey_count == 0
