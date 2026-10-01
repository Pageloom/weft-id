"""Pushed authorization requests (RFC 9126)."""

from datetime import datetime

from database._core import TenantArg, execute, fetchone
from psycopg.types.json import Json


def create_pushed_request(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    reference_hash: str,
    parameters: dict[str, str],
    expires_at: datetime,
) -> dict:
    """Store a pushed authorization request.

    Expired rows for the tenant are swept first, so the table holds only the
    requests that could still be redeemed.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not the client_id string)
        reference_hash: SHA-256 hex of the reference in the request_uri
        parameters: The authorization request parameters
        expires_at: When the request_uri stops working

    Returns:
        The new row's ``id`` and ``expires_at``
    """
    execute(
        tenant_id,
        "delete from oauth2_pushed_authorization_requests where expires_at < now()",
        {},
    )
    row = fetchone(
        tenant_id,
        """
        insert into oauth2_pushed_authorization_requests (
            tenant_id, client_id, reference_hash, parameters, expires_at
        )
        values (:tenant_id, :client_id, :reference_hash, :parameters, :expires_at)
        returning id, expires_at
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "reference_hash": reference_hash,
            "parameters": Json(parameters),
            "expires_at": expires_at,
        },
    )
    assert row is not None  # INSERT ... RETURNING always returns a row
    return row


def consume_pushed_request(
    tenant_id: TenantArg, client_id: str, reference_hash: str
) -> dict[str, str] | None:
    """Redeem a pushed authorization request, once.

    The row is deleted as it is read, so a request_uri works a single time.
    A request pushed by another client, or one that has expired, is left alone
    and not returned.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: OAuth2 client UUID of the client redeeming it
        reference_hash: SHA-256 hex of the reference in the request_uri

    Returns:
        The stored parameters, or None
    """
    row = fetchone(
        tenant_id,
        """
        delete from oauth2_pushed_authorization_requests
        where reference_hash = :reference_hash
          and client_id = :client_id
          and expires_at > now()
        returning parameters
        """,
        {"reference_hash": reference_hash, "client_id": client_id},
    )
    return row["parameters"] if row else None
