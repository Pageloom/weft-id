"""User core database operations (retrieval, creation, deletion)."""

from database._core import TenantArg, execute, fetchone


def get_user_by_id(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get a user by ID.

    Returns:
        User record with id, tenant_id, first_name, last_name, role, created_at,
        last_login, mfa_enabled, mfa_method, tz, locale, theme, is_inactivated,
        is_anonymized, inactivated_at, anonymized_at, reactivation_denied_at,
        saml_idp_id, saml_idp_name, has_password, password_reset_required
    """
    return fetchone(
        tenant_id,
        """
        select u.id, u.tenant_id, u.first_name, u.last_name, u.role, u.created_at, u.last_login,
               u.mfa_enabled, u.mfa_method, u.tz, u.locale, u.theme,
               u.is_inactivated, u.is_anonymized, u.inactivated_at, u.anonymized_at,
               u.reactivation_denied_at,
               u.saml_idp_id, idp.name as saml_idp_name,
               u.password_hash is not null as has_password,
               u.password_reset_required
        from users u
        left join saml_identity_providers idp on u.saml_idp_id = idp.id
        where u.id = :user_id
        """,
        {"user_id": user_id},
    )


def get_user_by_email(tenant_id: TenantArg, email: str) -> dict | None:
    """
    Get a user by email address (for login).

    Returns:
        Dict with user_id and password_hash, or None if not found or email not verified
    """
    return fetchone(
        tenant_id,
        """
        select ue.user_id, u.password_hash
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email and ue.verified_at is not null
        """,
        {"email": email},
    )


def get_user_by_email_with_status(tenant_id: TenantArg, email: str) -> dict | None:
    """
    Get full user record by verified email for authentication (SAML/OAuth).

    Returns:
        User record with id, first_name, last_name, role, inactivated_at,
        mfa_enabled, mfa_method, or None if not found or email not verified
    """
    return fetchone(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, u.role, u.inactivated_at,
               u.mfa_enabled, u.mfa_method
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email and ue.verified_at is not null
        """,
        {"email": email},
    )


def get_user_by_email_for_saml(tenant_id: TenantArg, email: str) -> dict | None:
    """
    Get user record by email regardless of verification status.

    Used for SAML authentication where the IdP assertion is authoritative
    for the email address. Returns the email_id and verification status
    so the caller can verify unverified emails.

    Returns:
        User record with id, first_name, last_name, role, inactivated_at,
        mfa_enabled, mfa_method, email_id, email_verified, saml_idp_id,
        password_hash, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, u.role, u.inactivated_at,
               u.mfa_enabled, u.mfa_method, u.saml_idp_id, u.password_hash,
               ue.id as email_id, ue.verified_at is not null as email_verified
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email
        """,
        {"email": email},
    )


def get_user_with_saml_info(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get user with SAML-related fields for admin display.

    Returns:
        User dict with saml_idp_id, saml_idp_name, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select u.id, u.tenant_id, u.first_name, u.last_name, u.role,
               u.created_at, u.last_login, u.mfa_enabled, u.mfa_method,
               u.tz, u.locale, u.theme, u.is_inactivated, u.is_anonymized,
               u.inactivated_at, u.anonymized_at, u.reactivation_denied_at,
               u.saml_idp_id, u.password_hash is not null as has_password,
               u.password_reset_required,
               idp.name as saml_idp_name
        from users u
        left join saml_identity_providers idp on u.saml_idp_id = idp.id
        where u.id = :user_id
        """,
        {"user_id": user_id},
    )


def create_user(
    tenant_id: TenantArg,
    tenant_id_value: str,
    first_name: str,
    last_name: str,
    email: str,
    role: str = "member",
) -> dict | None:
    """
    Create a new user account (admin operation).

    This creates a user WITHOUT a password. The user will need to set their password
    via the password reset flow when they receive their invitation email.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store in the record
        first_name: User's first name
        last_name: User's last name
        email: User's primary email address
        role: User role ('member', 'admin', or 'super_admin'). Defaults to 'member'.

    Returns:
        Dict with user_id and email_id, or None if insert failed
    """
    # Create user without password_hash (NULL)
    user = fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role, password_hash)
        values (:tenant_id, :first_name, :last_name, :role, null)
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
        },
    )

    if not user:
        return None

    return {"user_id": user["id"]}


def delete_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Delete a user and all associated data.

    This relies on cascading deletes for related records (emails, tokens, etc.).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to delete

    Returns:
        Number of rows deleted (0 or 1)

    Note:
        Service users (linked to OAuth2 clients) should not be deleted directly.
        Delete the OAuth2 client first to unlink the service user.
    """
    return execute(
        tenant_id,
        "delete from users where id = :user_id",
        {"user_id": user_id},
    )


def is_service_user(tenant_id: TenantArg, user_id: str) -> bool:
    """
    Check if a user is a service user (linked to a B2B OAuth2 client).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to check

    Returns:
        True if user is a service user, False otherwise
    """
    result = fetchone(
        tenant_id,
        """
        select 1 from oauth2_clients
        where service_user_id = :user_id
        limit 1
        """,
        {"user_id": user_id},
    )
    return result is not None
