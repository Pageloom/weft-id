"""OAuth2 device authorization grant database operations (RFC 8628)."""

from datetime import datetime

import oauth2
from database._core import TenantArg, execute, fetchone

# Rows are kept this long past expiry so a late poll still gets
# ``expired_token`` (not ``invalid_grant``) before the sweep removes them.
_EXPIRED_RETENTION_SECONDS = 3600

# A poll this much earlier than the interval is still accepted, so network
# jitter on a device that waits exactly ``interval`` seconds is not punished.
_POLL_SLACK_SECONDS = 1

# How many times to draw a fresh user code when one collides with a live row.
_USER_CODE_ATTEMPTS = 5

_ROW_COLUMNS = """
    id, client_id, scope, status, user_id, auth_time, poll_interval,
    expires_at, (expires_at <= now()) as expired
"""


def create_device_code(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    scope: str | None,
) -> dict:
    """
    Create a device authorization request.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not the client_id string)
        scope: Requested space-delimited scope string (optional)

    Returns:
        Dict with ``id``, ``device_code`` and ``user_code`` (both plain text,
        returned once), ``expires_at`` and ``poll_interval``
    """
    device_code = oauth2.generate_opaque_token("device")
    expires_at = oauth2.calculate_expires_at(oauth2.DEVICE_CODE_EXPIRY)

    for _ in range(_USER_CODE_ATTEMPTS):
        user_code = oauth2.generate_user_code()
        row = fetchone(
            tenant_id,
            """
            insert into oauth2_device_codes (
                tenant_id, client_id, device_code_hash, device_code_lookup,
                user_code_lookup, scope, poll_interval, expires_at
            )
            values (
                :tenant_id, :client_id, :device_code_hash, :device_code_lookup,
                :user_code_lookup, :scope, :poll_interval, :expires_at
            )
            on conflict (tenant_id, user_code_lookup) do nothing
            returning id, expires_at, poll_interval
            """,
            {
                "tenant_id": tenant_id_value,
                "client_id": client_id,
                "device_code_hash": oauth2.hash_token(device_code),
                "device_code_lookup": oauth2.token_lookup(device_code),
                "user_code_lookup": oauth2.token_lookup(user_code),
                "scope": scope,
                "poll_interval": oauth2.DEVICE_POLL_INTERVAL_SECONDS,
                "expires_at": expires_at,
            },
        )
        if row is not None:
            return {
                "id": str(row["id"]),
                "device_code": device_code,
                "user_code": user_code,
                "expires_at": row["expires_at"],
                "poll_interval": row["poll_interval"],
            }

    raise RuntimeError("Could not allocate a unique device user code")


def get_pending_by_user_code(tenant_id: TenantArg, user_code: str) -> dict | None:
    """
    Find a live, undecided request by its (normalised) user code.

    Returns:
        Dict with id, client_id, scope, expires_at; None when the code is
        unknown, expired, or already approved/denied
    """
    return fetchone(
        tenant_id,
        """
        select id, client_id, scope, expires_at
        from oauth2_device_codes
        where user_code_lookup = :lookup
          and status = 'pending'
          and expires_at > now()
        """,
        {"lookup": oauth2.token_lookup(user_code)},
    )


def decide_device_code(
    tenant_id: TenantArg,
    request_id: str,
    *,
    approved: bool,
    user_id: str,
    auth_time: datetime | None,
) -> dict | None:
    """
    Record the user's decision on a pending request (one decision only).

    Returns:
        Dict with id, client_id, scope; None when the request is no longer
        pending or has expired (another tab decided first, or it timed out)
    """
    return fetchone(
        tenant_id,
        """
        update oauth2_device_codes
        set status = :status, user_id = :user_id, auth_time = :auth_time,
            decided_at = now()
        where id = :id and status = 'pending' and expires_at > now()
        returning id, client_id, scope
        """,
        {
            "id": request_id,
            "status": "approved" if approved else "denied",
            "user_id": user_id,
            "auth_time": auth_time if approved else None,
        },
    )


def find_device_code(tenant_id: TenantArg, device_code: str, client_id: str) -> dict | None:
    """
    Look up a request by its device code, bound to the polling client.

    Expired rows are still returned (``expired`` is True) until the sweep
    removes them, so the caller can answer ``expired_token``.

    Returns:
        Dict with id, client_id, scope, status, user_id, auth_time,
        poll_interval, expires_at, expired; None when the code is unknown or
        was issued to another client
    """
    row = fetchone(
        tenant_id,
        f"""
        select device_code_hash, {_ROW_COLUMNS}
        from oauth2_device_codes
        where device_code_lookup = :lookup and client_id = :client_id
        """,
        {"lookup": oauth2.token_lookup(device_code), "client_id": client_id},
    )
    if row is None or not oauth2.verify_token_hash(device_code, row.pop("device_code_hash")):
        return None
    return row


def record_poll(tenant_id: TenantArg, request_id: str) -> dict | None:
    """
    Record a poll of a pending request and decide whether it came too soon.

    A poll earlier than ``poll_interval`` (less a small slack) after the
    previous one is a ``slow_down``: the interval grows by 5 seconds for this
    and every later poll (RFC 8628 section 3.5), capped at 300.

    Returns:
        Dict with ``slow_down`` (bool) and the resulting ``poll_interval``;
        None when the row is gone
    """
    return fetchone(
        tenant_id,
        """
        with prev as (
            select id, poll_interval,
                   coalesce(
                       last_polled_at > now() - make_interval(
                           secs => greatest(poll_interval - :slack, 0)
                       ),
                       false
                   ) as too_soon
            from oauth2_device_codes
            where id = :id
            for update
        )
        update oauth2_device_codes d
        set last_polled_at = now(),
            poll_interval = case
                when prev.too_soon then least(prev.poll_interval + 5, 300)
                else prev.poll_interval
            end
        from prev
        where d.id = prev.id
        returning prev.too_soon as slow_down, d.poll_interval
        """,
        {"id": request_id, "slack": _POLL_SLACK_SECONDS},
    )


def redeem_device_code(tenant_id: TenantArg, request_id: str) -> dict | None:
    """
    Mark an approved, unexpired request redeemed (exactly once).

    Returns:
        Dict with id, user_id, scope, auth_time; None when it was not
        approved, already redeemed (a concurrent poll won), or expired
    """
    return fetchone(
        tenant_id,
        """
        update oauth2_device_codes
        set status = 'redeemed'
        where id = :id and status = 'approved' and expires_at > now()
        returning id, user_id, scope, auth_time
        """,
        {"id": request_id},
    )


def cleanup_expired_device_codes(tenant_id: TenantArg) -> int:
    """
    Delete requests that expired more than an hour ago.

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        """
        delete from oauth2_device_codes
        where expires_at <= now() - make_interval(secs => :retention)
        """,
        {"retention": _EXPIRED_RETENTION_SECONDS},
    )
