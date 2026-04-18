"""Tenant authentication strength policy enforcement for users.

This module exposes helpers for checking whether a user satisfies the
tenant-wide required auth strength (`baseline` vs `enhanced`) and must
therefore be funneled into enhanced enrollment before reaching the
dashboard.

Policy values:
- `baseline`: email OTP, TOTP, and passkey all satisfy two-step verification.
- `enhanced`: only TOTP (and, in later iterations, passkey) satisfies it.

A user whose tenant is on `enhanced` and whose `mfa_method` is still `email`
must enroll in TOTP (or, later, a passkey) immediately after signing in.
"""

import database


def user_must_enroll_enhanced(tenant_id: str, user: dict) -> bool:
    """Return True if this user must enroll in a strong auth method now.

    Iteration 1 treats only TOTP as satisfying the enhanced policy. Iteration 4
    will extend this to also accept a registered passkey.

    Args:
        tenant_id: The tenant ID (used to look up policy).
        user: User dict including at least `mfa_method`.

    Returns:
        True if the user needs to enroll before continuing; False otherwise.
    """
    policy = database.security.get_required_auth_strength(tenant_id)
    if policy != "enhanced":
        return False

    return user.get("mfa_method") != "totp"
