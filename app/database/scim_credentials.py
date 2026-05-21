"""Outbound SCIM bearer credential database operations.

Bearer tokens issued to WeftID by downstream Service Providers. Stored as
Fernet-encrypted plaintext (`encrypted_plaintext`) so the outbound push
worker can send the value the downstream SP expects. Multiple active rows
per SP are supported for rotation-overlap windows.
"""

import re
from typing import cast

from ._core import TenantArg, execute, fetchall, fetchone, session

# Accept simple `<int> <unit>` interval expressions for overlap windows.
# Anything more exotic should be passed as an explicit `revoke_at` timestamp.
_INTERVAL_RE = re.compile(
    r"^\s*(\d+)\s+(seconds?|minutes?|hours?|days?|weeks?|months?|years?)\s*$",
    re.IGNORECASE,
)


def create_credential(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    created_by_user_id: str,
    encrypted_plaintext: bytes,
) -> dict:
    """Create a new SCIM bearer credential for a service provider.

    Args:
        tenant_id: Tenant scope for RLS.
        tenant_id_value: Tenant id as a string for the INSERT.
        sp_id: Service provider id this token belongs to.
        created_by_user_id: User id of the admin creating the token.
        encrypted_plaintext: Fernet-encrypted plaintext token (bytes) so the
            outbound push worker can recover the value it must send to the
            downstream SP.

    Returns:
        Dict with id, sp_id, tenant_id, created_by_user_id, created_at,
        revoked_at, last_used_at.
    """
    result = fetchone(
        tenant_id,
        """
        insert into sp_scim_credentials (
            tenant_id, sp_id, created_by_user_id, encrypted_plaintext
        ) values (
            :tenant_id, :sp_id, :created_by_user_id, :encrypted_plaintext
        )
        returning id, tenant_id, sp_id, created_by_user_id,
                  created_at, revoked_at, last_used_at
        """,
        {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
            "created_by_user_id": created_by_user_id,
            "encrypted_plaintext": encrypted_plaintext,
        },
    )
    # Defensive: should never happen on INSERT with RETURNING
    assert result is not None
    return result


def get_active_credential_for_outbound(
    tenant_id: TenantArg,
    sp_id: str,
) -> dict | None:
    """Look up the most recent non-revoked credential for outbound push.

    Picks the newest row where `revoked_at IS NULL OR revoked_at > now()`
    (i.e. still inside the rotation overlap window if any). Returns the
    `encrypted_plaintext` so the worker can decrypt it via the Fernet key.
    A row without `encrypted_plaintext` (legacy / test fixture) is skipped
    -- the worker dead-letters those with `no_credential_source`.

    Args:
        tenant_id: Tenant scope (RLS active when called from the worker
            inside a tenant-scoped session).
        sp_id: Service provider id.

    Returns:
        Dict with id, encrypted_plaintext, or None when no usable row.
    """
    return fetchone(
        tenant_id,
        """
        select id, encrypted_plaintext
        from sp_scim_credentials
        where sp_id = :sp_id
          and encrypted_plaintext is not null
          and (revoked_at is null or revoked_at > now())
        order by created_at desc
        limit 1
        """,
        {"sp_id": sp_id},
    )


def rotate_credential_atomic(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    existing_credential_id: str,
    created_by_user_id: str,
    encrypted_plaintext: bytes,
    overlap_hours: int,
) -> dict | None:
    """Mint a new credential and schedule the existing one for revocation atomically.

    Closes the read-then-write TOCTOU window where two concurrent
    rotates could both observe the same active credential, both insert
    a fresh row, and both schedule the original for revocation. The
    sequence is:

    1. `SELECT ... FOR UPDATE` the existing credential row -- blocks any
       concurrent rotate that tries to do the same.
    2. If the row is missing, already revoked, or scheduled for past
       revocation, return None so the caller can raise `NotFoundError`.
    3. Insert the new credential row.
    4. Schedule the existing row for revocation `overlap_hours` from now.
       `overlap_hours=0` revokes immediately (sets `revoked_at = now()`).
    5. Commit (on session exit).

    Both statements share a single connection / transaction so the row
    lock taken in step 1 holds through step 4. A concurrent rotate that
    arrives while we hold the lock will block on step 1 until we commit,
    by which time the row's `revoked_at` is no longer null and our
    re-check rejects it (returns None).

    Args:
        tenant_id: Tenant scope for RLS.
        tenant_id_value: Tenant id as a string for the INSERT row.
        sp_id: Service provider id.
        existing_credential_id: The credential being rotated out.
        created_by_user_id: Admin user id (audit field).
        encrypted_plaintext: Fernet-encrypted new token plaintext.
        overlap_hours: Grace window for the old token. 0 = revoke
            immediately. Must be 0..720 (caller validates the upper
            bound; the database does not).

    Returns:
        Dict for the newly-inserted credential row, or None when the
        existing credential is no longer rotatable (missing or already
        revoked in the past).
    """
    with session(tenant_id=tenant_id) as cur:
        # Step 1: lock the existing row and verify it belongs to the
        # named SP. Reject if missing or already revoked (any non-null
        # `revoked_at` means another caller has already rotated this row
        # or scheduled it for revocation -- the caller is racing).
        cur.execute(
            """
            SELECT id, revoked_at
            FROM sp_scim_credentials
            WHERE id = %(id)s AND sp_id = %(sp_id)s
            FOR UPDATE
            """,
            {"id": existing_credential_id, "sp_id": sp_id},
        )
        existing = cur.fetchone()
        if existing is None:
            return None
        revoked_at = existing.get("revoked_at")
        if revoked_at is not None:
            return None

        # Step 2: insert the new credential row.
        cur.execute(
            """
            INSERT INTO sp_scim_credentials (
                tenant_id, sp_id, created_by_user_id, encrypted_plaintext
            ) VALUES (
                %(tenant_id)s, %(sp_id)s, %(created_by_user_id)s, %(encrypted_plaintext)s
            )
            RETURNING id, tenant_id, sp_id, created_by_user_id,
                      created_at, revoked_at, last_used_at
            """,
            {
                "tenant_id": tenant_id_value,
                "sp_id": sp_id,
                "created_by_user_id": created_by_user_id,
                "encrypted_plaintext": encrypted_plaintext,
            },
        )
        new_row = cur.fetchone()
        assert new_row is not None  # INSERT ... RETURNING always returns a row

        # Step 3: schedule revocation of the old row (still locked).
        if overlap_hours == 0:
            cur.execute(
                """
                UPDATE sp_scim_credentials
                SET revoked_at = now()
                WHERE id = %(id)s AND revoked_at IS NULL
                """,
                {"id": existing_credential_id},
            )
        else:
            cur.execute(
                """
                UPDATE sp_scim_credentials
                SET revoked_at = now() + make_interval(hours => %(qty)s)
                WHERE id = %(id)s AND revoked_at IS NULL
                """,
                {"id": existing_credential_id, "qty": overlap_hours},
            )

        return cast(dict, new_row)


def list_active_credentials(tenant_id: TenantArg, sp_id: str) -> list[dict]:
    """List non-revoked credentials for a service provider, newest first.

    "Non-revoked" here means `revoked_at IS NULL` strictly. A credential
    whose `revoked_at` is set in the future is excluded (the column has
    been written, even if the row remains usable until that timestamp).
    Use `list_usable_credentials` for the rotation-aware listing the
    admin UI needs.
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, sp_id, created_by_user_id,
               created_at, revoked_at, last_used_at
        from sp_scim_credentials
        where sp_id = :sp_id and revoked_at is null
        order by created_at desc
        """,
        {"sp_id": sp_id},
    )


def list_usable_credentials(tenant_id: TenantArg, sp_id: str) -> list[dict]:
    """List credentials that are still accepted, newest first.

    A row is usable when `revoked_at IS NULL OR revoked_at > now()`. The
    rotation-overlap window keeps the old token usable for a configurable
    period after rotation; this listing surfaces both the new token and
    the pending-revocation old token so the admin UI can show "active"
    and "expiring at ..." badges side by side.
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, sp_id, created_by_user_id,
               created_at, revoked_at, last_used_at
        from sp_scim_credentials
        where sp_id = :sp_id
          and (revoked_at is null or revoked_at > now())
        order by created_at desc
        """,
        {"sp_id": sp_id},
    )


def list_all_credentials(tenant_id: TenantArg, sp_id: str) -> list[dict]:
    """List all credentials (including revoked) for a service provider, newest first."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, sp_id, created_by_user_id,
               created_at, revoked_at, last_used_at
        from sp_scim_credentials
        where sp_id = :sp_id
        order by created_at desc
        """,
        {"sp_id": sp_id},
    )


def mark_revoked(tenant_id: TenantArg, credential_id: str) -> int:
    """Revoke a credential immediately. Returns number of rows updated."""
    return execute(
        tenant_id,
        """
        update sp_scim_credentials
        set revoked_at = now()
        where id = :id and revoked_at is null
        """,
        {"id": credential_id},
    )


def schedule_revocation(
    tenant_id: TenantArg,
    credential_id: str,
    revoke_at: str | None = None,
    overlap_interval: str = "24 hours",
) -> int:
    """Schedule a credential for revocation after a grace window.

    Used during rotation so the old token stays valid during the overlap
    window. Pass `revoke_at` for an explicit timestamp, otherwise the
    revocation is scheduled `overlap_interval` from now.

    Returns:
        Number of rows updated.
    """
    if revoke_at is not None:
        return execute(
            tenant_id,
            """
            update sp_scim_credentials
            set revoked_at = :revoke_at
            where id = :id and revoked_at is null
            """,
            {"id": credential_id, "revoke_at": revoke_at},
        )
    # psycopg's named-param parser treats `::interval` as a named parameter,
    # so we use make_interval() with a parsed integer + named unit instead.
    match = _INTERVAL_RE.match(overlap_interval)
    if not match:
        raise ValueError(
            f"overlap_interval must be like '24 hours' or '7 days', got {overlap_interval!r}"
        )
    qty = int(match.group(1))
    unit = match.group(2).lower().rstrip("s")
    column = {
        "second": "secs",
        "minute": "mins",
        "hour": "hours",
        "day": "days",
        "week": "weeks",
        "month": "months",
        "year": "years",
    }[unit]
    return execute(
        tenant_id,
        f"""
        update sp_scim_credentials
        set revoked_at = now() + make_interval({column} => :qty)
        where id = :id and revoked_at is null
        """,
        {"id": credential_id, "qty": qty},
    )


def update_last_used(tenant_id: TenantArg, credential_id: str) -> int:
    """Mark a credential as having been used just now. Returns rows updated."""
    return execute(
        tenant_id,
        """
        update sp_scim_credentials
        set last_used_at = now()
        where id = :id
        """,
        {"id": credential_id},
    )
