"""User SAML IdP assignment database operations."""

from database._core import TenantArg, execute, fetchall, fetchone


def get_user_auth_info(tenant_id: TenantArg, email: str) -> dict | None:
    """
    Get user authentication routing info by email.

    Used by email-first login to determine auth method.

    Args:
        tenant_id: Tenant ID for scoping
        email: User's email address

    Returns:
        Dict with id, email, has_password, saml_idp_id,
        is_inactivated, or None if email not found/not verified.
    """
    return fetchone(
        tenant_id,
        """
        select u.id,
               ue.email,
               u.password_hash is not null as has_password,
               u.saml_idp_id,
               u.is_inactivated
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email and ue.verified_at is not null
        """,
        {"email": email.lower()},
    )


def update_user_saml_idp(
    tenant_id: TenantArg,
    user_id: str,
    saml_idp_id: str | None,
) -> int:
    """
    Update user's SAML IdP assignment.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to update
        saml_idp_id: IdP ID to assign, or None for password-only

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update users
        set saml_idp_id = :saml_idp_id
        where id = :user_id
        """,
        {"user_id": user_id, "saml_idp_id": saml_idp_id},
    )


def wipe_user_password(tenant_id: TenantArg, user_id: str) -> int:
    """
    Wipe user's password hash (security measure when assigning to SAML IdP).

    This ensures SAML-authenticated users cannot fall back to password auth.
    MFA settings are preserved.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to update

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set password_hash = null where id = :user_id",
        {"user_id": user_id},
    )


def unverify_user_emails(tenant_id: TenantArg, user_id: str) -> int:
    """
    Unverify all email addresses for a user (security measure when removing from IdP).

    This ensures users removed from SAML IdP must re-verify their emails
    before using password authentication.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID whose emails should be unverified

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update user_emails
        set verified_at = null, verify_nonce = verify_nonce + 1
        where user_id = :user_id and verified_at is not null
        """,
        {"user_id": user_id},
    )


def get_users_by_email_domain(tenant_id: TenantArg, domain: str) -> list[dict]:
    """
    Get all users with verified emails in a specific domain.

    Used when binding a domain to an IdP to find affected users.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Email domain (e.g., 'company.com')

    Returns:
        List of user dicts with id, saml_idp_id, has_password
    """
    # Build the pattern in Python to avoid SQL placeholder issues with %
    pattern = f"%@{domain.lower()}"
    return fetchall(
        tenant_id,
        """
        select distinct u.id, u.saml_idp_id,
               u.password_hash is not null as has_password
        from users u
        join user_emails ue on ue.user_id = u.id
        where ue.email like :pattern
          and ue.verified_at is not null
        """,
        {"pattern": pattern},
    )


def bulk_assign_users_to_idp(
    tenant_id: TenantArg,
    user_ids: list[str],
    saml_idp_id: str,
) -> int:
    """
    Assign multiple users to a SAML IdP, preserving passwords.

    Used when binding a domain to an IdP. All users with that domain
    are immediately assigned to the IdP. Passwords are preserved but
    unusable while saml_idp_id is set.

    Args:
        tenant_id: Tenant ID for scoping
        user_ids: List of user IDs to assign
        saml_idp_id: IdP ID to assign users to

    Returns:
        Number of rows affected
    """
    if not user_ids:
        return 0
    return execute(
        tenant_id,
        """
        update users
        set saml_idp_id = :saml_idp_id
        where id = any(:user_ids)
        """,
        {"saml_idp_id": saml_idp_id, "user_ids": user_ids},
    )


def bulk_inactivate_users(
    tenant_id: TenantArg,
    user_ids: list[str],
) -> int:
    """
    Inactivate multiple users and clear their IdP assignment.

    Used when unbinding a domain. Affected users lose IdP access
    and are inactivated.

    Args:
        tenant_id: Tenant ID for scoping
        user_ids: List of user IDs to inactivate

    Returns:
        Number of rows affected
    """
    if not user_ids:
        return 0
    return execute(
        tenant_id,
        """
        update users
        set saml_idp_id = null, is_inactivated = true, inactivated_at = now()
        where id = any(:user_ids)
        """,
        {"user_ids": user_ids},
    )


def bulk_unverify_emails(tenant_id: TenantArg, user_ids: list[str]) -> int:
    """
    Unverify all email addresses for multiple users.

    Used when unbinding a domain. Affected users must re-verify
    their emails before using password authentication.

    Args:
        tenant_id: Tenant ID for scoping
        user_ids: List of user IDs whose emails should be unverified

    Returns:
        Number of rows affected
    """
    if not user_ids:
        return 0
    return execute(
        tenant_id,
        """
        update user_emails
        set verified_at = null, verify_nonce = verify_nonce + 1
        where user_id = any(:user_ids) and verified_at is not null
        """,
        {"user_ids": user_ids},
    )
