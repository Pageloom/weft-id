"""User email address database operations."""

from ._core import TenantArg, execute, fetchall, fetchone


def get_primary_email(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get the primary email address for a user.

    Returns:
        Dict with email field, or None if no primary email found
    """
    return fetchone(
        tenant_id,
        "select email from user_emails where user_id = :user_id and is_primary = true",
        {"user_id": user_id},
    )


def get_user_with_primary_email(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get user info along with their primary email.

    Returns:
        Dict with id and email fields, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select u.id, ue.email
        from users u
        join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where u.id = :user_id
        """,
        {"user_id": user_id},
    )


def list_user_emails(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """
    List all email addresses for a user.

    Returns:
        List of email dicts with id, email, is_primary, verified_at, created_at
    """
    return fetchall(
        tenant_id,
        """
        select id, email, is_primary, verified_at, created_at
        from user_emails
        where user_id = :user_id
        order by is_primary desc, created_at asc
        """,
        {"user_id": user_id},
    )


def email_exists(tenant_id: TenantArg, email: str) -> bool:
    """
    Check if an email address already exists in the tenant.

    Returns:
        True if email exists, False otherwise
    """
    result = fetchone(
        tenant_id,
        "select id from user_emails where email = :email",
        {"email": email},
    )
    return result is not None


def add_email(tenant_id: TenantArg, user_id: str, email: str, tenant_id_value: str) -> dict | None:
    """
    Add a new email address to a user's account (unverified).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID
        email: Email address to add
        tenant_id_value: The actual tenant ID value to store in the record

    Returns:
        Dict with id and verify_nonce, or None if insert failed
    """
    return fetchone(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, false, null)
        returning id, verify_nonce
        """,
        {"tenant_id": tenant_id_value, "user_id": user_id, "email": email},
    )


def get_email_by_id(tenant_id: TenantArg, email_id: str, user_id: str) -> dict | None:
    """
    Get an email record by ID for a specific user.

    Returns:
        Dict with id, email, is_primary, verified_at fields, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, email, is_primary, verified_at
        from user_emails
        where id = :email_id and user_id = :user_id
        """,
        {"email_id": email_id, "user_id": user_id},
    )


def get_email_for_verification(tenant_id: TenantArg, email_id: str) -> dict | None:
    """
    Get email info for verification process.

    Returns:
        Dict with id, user_id, email, verified_at, verify_nonce, set_password_nonce,
        or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, user_id, email, verified_at, verify_nonce, set_password_nonce
        from user_emails
        where id = :email_id
        """,
        {"email_id": email_id},
    )


def get_email_with_nonce(tenant_id: TenantArg, email_id: str, user_id: str) -> dict | None:
    """
    Get email with verification nonce for resending verification.

    Returns:
        Dict with id, email, verify_nonce, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, email, verify_nonce from user_emails
        where id = :email_id and user_id = :user_id
        """,
        {"email_id": email_id, "user_id": user_id},
    )


def verify_email(tenant_id: TenantArg, email_id: str) -> int:
    """
    Mark an email as verified and increment the nonce.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update user_emails
        set verified_at = now(), verify_nonce = verify_nonce + 1
        where id = :email_id
        """,
        {"email_id": email_id},
    )


def increment_set_password_nonce(tenant_id: TenantArg, email_id: str) -> int:
    """
    Increment the set_password_nonce for an email, invalidating the current
    set-password link.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update user_emails
        set set_password_nonce = set_password_nonce + 1
        where id = :email_id
        """,
        {"email_id": email_id},
    )


def unset_primary_emails(tenant_id: TenantArg, user_id: str) -> int:
    """
    Unset all primary email flags for a user.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update user_emails set is_primary = false where user_id = :user_id and is_primary = true",
        {"user_id": user_id},
    )


def set_primary_email(tenant_id: TenantArg, email_id: str) -> int:
    """
    Set an email as primary.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update user_emails set is_primary = true where id = :email_id",
        {"email_id": email_id},
    )


def delete_email(tenant_id: TenantArg, email_id: str) -> int:
    """
    Delete an email address.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "delete from user_emails where id = :email_id",
        {"email_id": email_id},
    )


def add_verified_email(
    tenant_id: TenantArg,
    user_id: str,
    email: str,
    tenant_id_value: str,
    is_primary: bool = False,
) -> dict | None:
    """
    Add a new email address to a user's account (pre-verified, for admin use).

    This is used when an admin adds an email to a user's account. The email
    is automatically marked as verified.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID
        email: Email address to add
        tenant_id_value: The actual tenant ID value to store in the record
        is_primary: Whether this should be the primary email (default: False)

    Returns:
        Dict with id and email, or None if insert failed
    """
    return fetchone(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, :is_primary, now())
        returning id, email, set_password_nonce
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "email": email,
            "is_primary": is_primary,
        },
    )


def count_user_emails(tenant_id: TenantArg, user_id: str) -> int:
    """
    Count the number of email addresses for a user.

    Returns:
        Number of email addresses
    """
    result = fetchone(
        tenant_id,
        "select count(*) as count from user_emails where user_id = :user_id",
        {"user_id": user_id},
    )
    return result["count"] if result else 0


def anonymize_user_emails(tenant_id: TenantArg, user_id: str) -> int:
    """
    Anonymize all email addresses for a user (GDPR anonymization).

    Replaces email addresses with anonymized placeholders using the email record ID.
    Format: anon-{email_id}@anonymized.local

    This preserves the email records for referential integrity while removing PII.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID whose emails to anonymize

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update user_emails
        set email = 'anon-' || cast(id as text) || '@anonymized.example.com',
            verified_at = null
        where user_id = :user_id
        """,
        {"user_id": user_id},
    )
