"""WebAuthn (passkey) credential database operations."""

from ._core import TenantArg, execute, fetchall, fetchone


def create_credential(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    credential_id: bytes,
    public_key: bytes,
    name: str,
    sign_count: int,
    aaguid: str | None,
    transports: list[str] | None,
    backup_eligible: bool,
    backup_state: bool,
) -> dict:
    """
    Create a new webauthn credential for a user.

    Returns:
        The inserted row with id, created_at, etc.
    """
    result = fetchone(
        tenant_id,
        """
        insert into webauthn_credentials (
            tenant_id, user_id, credential_id, public_key, sign_count,
            name, aaguid, transports, backup_eligible, backup_state
        ) values (
            :tenant_id, :user_id, :credential_id, :public_key, :sign_count,
            :name, :aaguid, :transports, :backup_eligible, :backup_state
        )
        returning id, tenant_id, user_id, credential_id, public_key, sign_count,
                  name, aaguid, transports, backup_eligible, backup_state,
                  created_at, last_used_at
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "credential_id": credential_id,
            "public_key": public_key,
            "sign_count": sign_count,
            "name": name,
            "aaguid": aaguid,
            "transports": transports,
            "backup_eligible": backup_eligible,
            "backup_state": backup_state,
        },
    )
    # Defensive: should never happen on INSERT with RETURNING
    assert result is not None
    return result


def list_credentials(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """
    List all webauthn credentials for a user, most recently created first.
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, user_id, credential_id, public_key, sign_count,
               name, aaguid, transports, backup_eligible, backup_state,
               created_at, last_used_at
        from webauthn_credentials
        where user_id = :user_id
        order by created_at desc
        """,
        {"user_id": user_id},
    )


def get_credential(tenant_id: TenantArg, credential_uuid: str) -> dict | None:
    """
    Get a credential by its database PK (row UUID).

    Note: credential_uuid is the `webauthn_credentials.id` column, not the
    WebAuthn `credential_id` bytes returned by the authenticator.
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, user_id, credential_id, public_key, sign_count,
               name, aaguid, transports, backup_eligible, backup_state,
               created_at, last_used_at
        from webauthn_credentials
        where id = :id
        """,
        {"id": credential_uuid},
    )


def rename_credential(
    tenant_id: TenantArg,
    credential_uuid: str,
    user_id: str,
    new_name: str,
) -> int:
    """
    Rename a credential. Scoped by user_id to prevent cross-user writes.

    Returns:
        Number of rows affected (0 if not found or owned by a different user).
    """
    return execute(
        tenant_id,
        """
        update webauthn_credentials
        set name = :name
        where id = :id and user_id = :user_id
        """,
        {"id": credential_uuid, "user_id": user_id, "name": new_name},
    )


def delete_credential(
    tenant_id: TenantArg,
    credential_uuid: str,
    user_id: str,
) -> int:
    """
    Delete a credential. Scoped by user_id to prevent cross-user writes.

    Returns:
        Number of rows affected (0 if not found or owned by a different user).
    """
    return execute(
        tenant_id,
        """
        delete from webauthn_credentials
        where id = :id and user_id = :user_id
        """,
        {"id": credential_uuid, "user_id": user_id},
    )


def count_credentials(tenant_id: TenantArg, user_id: str) -> int:
    """
    Count webauthn credentials for a user.
    """
    row = fetchone(
        tenant_id,
        """
        select count(*) as c
        from webauthn_credentials
        where user_id = :user_id
        """,
        {"user_id": user_id},
    )
    if not row:
        return 0
    return int(row["c"])
