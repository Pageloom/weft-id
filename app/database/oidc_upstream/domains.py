"""OIDC upstream domain binding database operations.

Mirrors ``database.saml.domains`` for the consuming (relying-party)
direction of OIDC. Maps a ``tenant_privileged_domains`` row to an OIDC
connection so the email-first login flow can route unknown users to the
connection's JIT flow.

Every query is RLS-scoped via the ``tenant_id`` argument to the database
helpers, so only the calling tenant's rows are ever visible.
"""

from database._core import TenantArg, execute, fetchall, fetchone


def get_domain_bindings_for_connection(tenant_id: TenantArg, connection_id: str) -> list[dict]:
    """Get all domain bindings for a specific OIDC connection.

    Returns a list of dicts with id, domain_id, domain, idp_id, created_at.
    """
    return fetchall(
        tenant_id,
        """
        select db.id, db.domain_id, pd.domain, db.idp_id, db.created_at
        from oidc_idp_domain_bindings db
        join tenant_privileged_domains pd on db.domain_id = pd.id
        where db.idp_id = :connection_id
        order by pd.domain
        """,
        {"connection_id": connection_id},
    )


def get_connection_for_domain(tenant_id: TenantArg, domain: str) -> dict | None:
    """Get the OIDC connection bound to a specific email domain.

    Returns the connection row (or None) if the domain is bound to an enabled
    OIDC connection.
    """
    return fetchone(
        tenant_id,
        """
        select conn.id, conn.tenant_id, conn.name, conn.provider_type, conn.issuer,
               conn.discovery_url, conn.authorization_endpoint, conn.token_endpoint,
               conn.userinfo_endpoint, conn.jwks_uri, conn.discovery_fetched_at,
               conn.discovery_error, conn.client_id, conn.client_secret_enc,
               conn.scopes, conn.claim_mapping, conn.correlation_claim,
               conn.group_claim_source, conn.hosted_domain, conn.entra_tenant_id,
               conn.is_enabled, conn.is_default, conn.require_platform_mfa,
               conn.jit_provisioning, conn.allow_email_linking,
               conn.created_by, conn.created_at, conn.updated_at
        from oidc_idp_domain_bindings db
        join tenant_privileged_domains pd on db.domain_id = pd.id
        join oidc_idp_connections conn on db.idp_id = conn.id
        where pd.domain = :domain and conn.is_enabled = true
        """,
        {"domain": domain.lower()},
    )


def bind_domain_to_connection(
    tenant_id: TenantArg,
    tenant_id_value: str,
    domain_id: str,
    connection_id: str,
    created_by: str,
) -> dict | None:
    """Bind a privileged domain to an OIDC connection (upsert).

    If the domain is already bound to an OIDC connection, updates to the new
    connection. Returns the binding row (id, domain_id, idp_id, created_at).
    """
    return fetchone(
        tenant_id,
        """
        insert into oidc_idp_domain_bindings (tenant_id, domain_id, idp_id, created_by)
        values (:tenant_id, :domain_id, :connection_id, :created_by)
        on conflict (tenant_id, domain_id)
        do update set idp_id = :connection_id, created_by = :created_by, created_at = now()
        returning id, domain_id, idp_id, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "domain_id": domain_id,
            "connection_id": connection_id,
            "created_by": created_by,
        },
    )


def unbind_domain_from_connection(tenant_id: TenantArg, domain_id: str) -> int:
    """Remove a domain-to-OIDC-connection binding. Returns rows deleted."""
    return execute(
        tenant_id,
        "delete from oidc_idp_domain_bindings where domain_id = :domain_id",
        {"domain_id": domain_id},
    )


def get_domain_binding_by_domain_id(tenant_id: TenantArg, domain_id: str) -> dict | None:
    """Get the OIDC binding for a specific domain ID, or None if not bound."""
    return fetchone(
        tenant_id,
        """
        select db.id, db.domain_id, db.idp_id, pd.domain, conn.name as connection_name
        from oidc_idp_domain_bindings db
        join tenant_privileged_domains pd on db.domain_id = pd.id
        join oidc_idp_connections conn on db.idp_id = conn.id
        where db.domain_id = :domain_id
        """,
        {"domain_id": domain_id},
    )


def get_unbound_domains(tenant_id: TenantArg) -> list[dict]:
    """Get privileged domains not bound to any OIDC connection.

    Returns a list of dicts with id, domain.
    """
    return fetchall(
        tenant_id,
        """
        select pd.id, pd.domain
        from tenant_privileged_domains pd
        left join oidc_idp_domain_bindings db on pd.id = db.domain_id
        left join saml_idp_domain_bindings sb on pd.id = sb.domain_id
        where db.id is null and sb.id is null
        order by pd.domain
        """,
        {},
    )
