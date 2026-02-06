"""SAML debug entry database operations."""

from database._core import TenantArg, fetchall, fetchone


def store_debug_entry(
    tenant_id: TenantArg,
    tenant_id_value: str,
    error_type: str,
    error_detail: str | None = None,
    idp_id: str | None = None,
    idp_name: str | None = None,
    saml_response_b64: str | None = None,
    saml_response_xml: str | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
) -> dict | None:
    """
    Store a SAML debug entry for a failed authentication.

    Args:
        tenant_id: Tenant context for RLS
        tenant_id_value: Tenant ID value
        error_type: Type of error (e.g., 'signature_error', 'expired', 'invalid_response')
        error_detail: Detailed error message
        idp_id: ID of the IdP that caused the failure (if known)
        idp_name: Name of the IdP (for display even if IdP is deleted)
        saml_response_b64: Base64-encoded SAML response
        saml_response_xml: Decoded XML content
        request_ip: IP address of the request
        user_agent: User agent string

    Returns:
        Dict with the created debug entry
    """
    return fetchone(
        tenant_id,
        """
        insert into saml_debug_entries (
            tenant_id, idp_id, idp_name, error_type, error_detail,
            saml_response_b64, saml_response_xml, request_ip, user_agent
        )
        values (
            :tenant_id, :idp_id, :idp_name, :error_type, :error_detail,
            :saml_response_b64, :saml_response_xml, :request_ip, :user_agent
        )
        returning id, tenant_id, idp_id, idp_name, error_type, error_detail,
                  saml_response_b64, saml_response_xml, request_ip, user_agent, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "idp_id": idp_id,
            "idp_name": idp_name,
            "error_type": error_type,
            "error_detail": error_detail,
            "saml_response_b64": saml_response_b64,
            "saml_response_xml": saml_response_xml,
            "request_ip": request_ip,
            "user_agent": user_agent,
        },
    )


def get_debug_entries(
    tenant_id: TenantArg,
    limit: int = 50,
) -> list[dict]:
    """
    Get recent SAML debug entries for a tenant.

    Args:
        tenant_id: Tenant context for RLS
        limit: Maximum number of entries to return

    Returns:
        List of debug entry dicts, most recent first
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, idp_id, idp_name, error_type, error_detail,
               saml_response_b64, saml_response_xml, request_ip, user_agent, created_at
        from saml_debug_entries
        order by created_at desc
        limit :limit
        """,
        {"limit": limit},
    )


def get_debug_entry(
    tenant_id: TenantArg,
    entry_id: str,
) -> dict | None:
    """
    Get a specific SAML debug entry.

    Args:
        tenant_id: Tenant context for RLS
        entry_id: Debug entry UUID

    Returns:
        Debug entry dict or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, idp_id, idp_name, error_type, error_detail,
               saml_response_b64, saml_response_xml, request_ip, user_agent, created_at
        from saml_debug_entries
        where id = :entry_id
        """,
        {"entry_id": entry_id},
    )


def delete_old_debug_entries(hours: int = 24) -> int:
    """
    Delete debug entries older than the specified hours.

    Does not use RLS (called by background job).

    Args:
        hours: Age threshold in hours (default 24)

    Returns:
        Number of entries deleted
    """
    from database._core import get_pool
    from psycopg.rows import dict_row

    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                delete from saml_debug_entries
                where created_at < now() - interval '%s hours'
                """,
                (hours,),
            )
            return cur.rowcount
