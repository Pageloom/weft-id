"""Protected domain database operations.

A protected domain is a real DNS domain a tenant registers so WeftID can act as
its forward-auth authority. Ownership is proven via a DNS-TXT challenge before
the domain becomes 'verified'. All queries are RLS-scoped by tenant.
"""

from database._core import TenantArg, execute, fetchall, fetchone

_COLUMNS = """id, tenant_id, domain, portal_host, verification_status,
              verification_token, verified_at, enabled, created_by,
              created_at, updated_at"""


def list_protected_domains(tenant_id: TenantArg) -> list[dict]:
    """List all protected domains for a tenant.

    Returns:
        List of protected-domain dicts ordered by created_at desc.
    """
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from protected_domains
        order by created_at desc
        """,
        {},
    )


def get_protected_domain(tenant_id: TenantArg, domain_id: str) -> dict | None:
    """Get a protected domain by ID.

    Returns:
        Protected-domain dict, or None if not found.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from protected_domains
        where id = :domain_id
        """,
        {"domain_id": domain_id},
    )


def get_protected_domain_by_domain(tenant_id: TenantArg, domain: str) -> dict | None:
    """Get a protected domain by its domain name within a tenant.

    Returns:
        Protected-domain dict, or None if not found.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from protected_domains
        where domain = :domain
        """,
        {"domain": domain},
    )


def get_protected_domain_by_portal_host(tenant_id: TenantArg, portal_host: str) -> dict | None:
    """Get a protected domain by its portal host.

    The portal host is globally unique, so this can be used with the UNSCOPED
    sentinel for the pre-auth ask endpoint and host->tenant resolution.

    Returns:
        Protected-domain dict, or None if not found.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from protected_domains
        where portal_host = :portal_host
        """,
        {"portal_host": portal_host},
    )


def create_protected_domain(
    tenant_id: TenantArg,
    tenant_id_value: str,
    domain: str,
    portal_host: str,
    created_by: str,
    verification_token: str | None = None,
    verification_status: str = "pending",
    enabled: bool = True,
) -> dict | None:
    """Create a protected domain.

    Returns:
        Created protected-domain dict, or None on failure.
    """
    return fetchone(
        tenant_id,
        f"""
        insert into protected_domains (
            tenant_id, domain, portal_host, verification_status,
            verification_token, enabled, created_by
        )
        values (
            :tenant_id, :domain, :portal_host, :verification_status,
            :verification_token, :enabled, :created_by
        )
        returning {_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "domain": domain,
            "portal_host": portal_host,
            "verification_status": verification_status,
            "verification_token": verification_token,
            "enabled": enabled,
            "created_by": created_by,
        },
    )


def update_protected_domain(
    tenant_id: TenantArg,
    domain_id: str,
    **fields: object,
) -> dict | None:
    """Update a protected domain's mutable fields.

    Only the provided keyword arguments are updated. Allowed keys:
    portal_host, verification_status, verification_token, verified_at, enabled.

    Returns:
        Updated protected-domain dict, or None if not found.
    """
    allowed = {
        "portal_host",
        "verification_status",
        "verification_token",
        "verified_at",
        "enabled",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_protected_domain(tenant_id, domain_id)

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    params: dict = {**updates, "domain_id": domain_id}

    return fetchone(
        tenant_id,
        f"""
        update protected_domains
        set {set_clause}
        where id = :domain_id
        returning {_COLUMNS}
        """,
        params,
    )


def delete_protected_domain(tenant_id: TenantArg, domain_id: str) -> int:
    """Delete a protected domain (cascades to its proxy apps and their grants).

    Returns:
        Number of rows deleted (0 or 1).
    """
    return execute(
        tenant_id,
        """
        delete from protected_domains
        where id = :domain_id
        """,
        {"domain_id": domain_id},
    )
