"""MFA (Multi-Factor Authentication) database operations."""

from datetime import datetime

from ._core import TenantArg, execute, fetchall, fetchone


def enable_mfa(tenant_id: TenantArg, user_id: str, method: str) -> int:
    """
    Enable MFA for a user with the specified method.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        method: MFA method ('email' or 'totp')

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set mfa_enabled = true, mfa_method = :method where id = :user_id",
        {"method": method, "user_id": user_id},
    )


def set_mfa_method(tenant_id: TenantArg, user_id: str, method: str) -> int:
    """
    Set the MFA method for a user (when downgrading from TOTP to email).

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        method: MFA method ('email' or 'totp')

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set mfa_method = :method where id = :user_id",
        {"method": method, "user_id": user_id},
    )


# TOTP operations


def create_totp_secret(
    tenant_id: TenantArg, user_id: str, secret_encrypted: str, tenant_id_value: str
) -> int:
    """
    Store an unverified TOTP secret for a user.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID
        secret_encrypted: Encrypted TOTP secret
        tenant_id_value: The actual tenant ID value to store in the record

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        insert into mfa_totp (tenant_id, user_id, secret_encrypted, method)
        values (:tenant_id, :user_id, :secret_encrypted, 'totp')
        on conflict (user_id, method) do update
        set secret_encrypted = excluded.secret_encrypted,
            verified_at = null
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "secret_encrypted": secret_encrypted,
        },
    )


def get_totp_secret(tenant_id: TenantArg, user_id: str, method: str) -> dict | None:
    """
    Get the encrypted TOTP secret for a user.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        method: MFA method ('totp')

    Returns:
        Dict with secret_encrypted field, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select secret_encrypted from mfa_totp
        where user_id = :user_id and method = :method
        """,
        {"user_id": user_id, "method": method},
    )


def get_verified_totp_secret(tenant_id: TenantArg, user_id: str, method: str) -> dict | None:
    """
    Get the encrypted TOTP secret for a user (only if verified).

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        method: MFA method ('totp')

    Returns:
        Dict with secret_encrypted field, or None if not found or not verified
    """
    return fetchone(
        tenant_id,
        """
        select secret_encrypted from mfa_totp
        where user_id = :user_id and method = :method and verified_at is not null
        """,
        {"user_id": user_id, "method": method},
    )


def verify_totp_secret(tenant_id: TenantArg, user_id: str, method: str) -> int:
    """
    Mark a TOTP secret as verified.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        method: MFA method ('totp')

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update mfa_totp set verified_at = now() where user_id = :user_id and method = :method",
        {"user_id": user_id, "method": method},
    )


def delete_totp_secrets(tenant_id: TenantArg, user_id: str) -> int:
    """
    Delete all TOTP secrets for a user (when downgrading to email MFA).

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "delete from mfa_totp where user_id = :user_id",
        {"user_id": user_id},
    )


# Email OTP operations
def create_email_otp(
    tenant_id: TenantArg,
    user_id: str,
    code_hash: str,
    expires_at: datetime,
    tenant_id_value: str,
) -> int:
    """
    Create an email OTP code.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID
        code_hash: SHA-256 hash of the OTP code
        expires_at: When the code expires
        tenant_id_value: The actual tenant ID value to store in the record

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        insert into mfa_email_codes (tenant_id, user_id, code_hash, expires_at)
        values (:tenant_id, :user_id, :code_hash, :expires_at)
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "code_hash": code_hash,
            "expires_at": expires_at,
        },
    )


def verify_email_otp(tenant_id: TenantArg, user_id: str, code_hash: str) -> bool:
    """
    Verify an email OTP code and mark it as used.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        code_hash: SHA-256 hash of the code to verify

    Returns:
        True if code was valid and marked as used, False otherwise
    """
    # Find valid, unused, non-expired code
    email_code = fetchone(
        tenant_id,
        """
        select id from mfa_email_codes
        where user_id = :user_id
          and code_hash = :code_hash
          and used_at is null
          and expires_at > now()
        order by created_at desc
        limit 1
        """,
        {"user_id": user_id, "code_hash": code_hash},
    )

    if not email_code:
        return False

    # Mark as used
    execute(
        tenant_id,
        "update mfa_email_codes set used_at = now() where id = :id",
        {"id": email_code["id"]},
    )

    return True


# Backup codes operations


def list_backup_codes(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """
    List all backup codes for a user.

    Returns:
        List of dicts with id, code_hash, used_at fields
    """
    return fetchall(
        tenant_id,
        """
        select id, code_hash, used_at from mfa_backup_codes
        where user_id = :user_id
        order by created_at asc
        """,
        {"user_id": user_id},
    )


def create_backup_code(
    tenant_id: TenantArg, user_id: str, code_hash: str, tenant_id_value: str
) -> int:
    """
    Create a single backup code.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID
        code_hash: SHA-256 hash of the backup code
        tenant_id_value: The actual tenant ID value to store in the record

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        insert into mfa_backup_codes (tenant_id, user_id, code_hash)
        values (:tenant_id, :user_id, :code_hash)
        """,
        {"tenant_id": tenant_id_value, "user_id": user_id, "code_hash": code_hash},
    )


def verify_backup_code(tenant_id: TenantArg, user_id: str, code_hash: str) -> bool:
    """
    Verify a backup code and mark it as used.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        code_hash: SHA-256 hash of the code to verify

    Returns:
        True if code was valid and marked as used, False otherwise
    """
    # Find unused backup code
    backup_code = fetchone(
        tenant_id,
        """
        select id from mfa_backup_codes
        where user_id = :user_id
          and code_hash = :code_hash
          and used_at is null
        """,
        {"user_id": user_id, "code_hash": code_hash},
    )

    if not backup_code:
        return False

    # Mark as used
    execute(
        tenant_id,
        "update mfa_backup_codes set used_at = now() where id = :id",
        {"id": backup_code["id"]},
    )

    return True


def delete_backup_codes(tenant_id: TenantArg, user_id: str) -> int:
    """
    Delete all backup codes for a user.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "delete from mfa_backup_codes where user_id = :user_id",
        {"user_id": user_id},
    )
