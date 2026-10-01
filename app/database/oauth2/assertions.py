"""OAuth2 client assertion replay store (RFC 7523 section 3, ``private_key_jwt``)."""

from datetime import datetime

from database._core import TenantArg, execute, fetchone


def record_client_assertion_jti(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    jti: str,
    expires_at: datetime,
) -> bool:
    """Record the ``jti`` of an accepted client assertion, once.

    Expired rows for the tenant are swept first, so the table holds only the
    assertions that could still be replayed.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not the client_id string)
        jti: The assertion's ``jti`` claim
        expires_at: The assertion's ``exp``; the row is kept until then

    Returns:
        True when the jti was new, False when this client already used it
        (a replay).
    """
    execute(
        tenant_id,
        "delete from oauth2_client_assertion_jtis where expires_at < now()",
        {},
    )
    row = fetchone(
        tenant_id,
        """
        insert into oauth2_client_assertion_jtis (tenant_id, client_id, jti, expires_at)
        values (:tenant_id, :client_id, :jti, :expires_at)
        on conflict (tenant_id, client_id, jti) do nothing
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "jti": jti,
            "expires_at": expires_at,
        },
    )
    return row is not None
