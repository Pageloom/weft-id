"""OIDC upstream connection database operations.

Mirrors ``database.saml.providers`` for the consuming (relying-party)
direction of OIDC. Every query is RLS-scoped via the ``tenant_id`` argument
to the database helpers, so only the calling tenant's rows are ever visible;
the SELECT/UPDATE statements therefore need no explicit tenant predicate.

The client secret is stored encrypted at rest (``client_secret_enc``) and is
never decrypted in this layer -- the service layer owns encryption/decryption
via the Fernet helper.
"""

import json
from typing import Any

from database._core import TenantArg, execute, fetchall, fetchone

_COLUMNS = """
    id, tenant_id, name, provider_type, issuer, discovery_url,
    authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
    discovery_fetched_at, discovery_error, client_id, client_secret_enc,
    scopes, claim_mapping, correlation_claim, group_claim_source,
    hosted_domain, entra_tenant_id, is_enabled, is_default,
    require_platform_mfa, jit_provisioning, allow_email_linking,
    created_by, created_at, updated_at
"""


def list_connections(tenant_id: TenantArg) -> list[dict]:
    """List all OIDC connections for a tenant, newest first."""
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_connections
        order by created_at desc
        """,
        {},
    )


def get_connection(tenant_id: TenantArg, connection_id: str) -> dict | None:
    """Get an OIDC connection by ID, or None if not found."""
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_connections
        where id = :connection_id
        """,
        {"connection_id": connection_id},
    )


def get_connection_by_issuer(tenant_id: TenantArg, issuer: str) -> dict | None:
    """Get an OIDC connection by issuer, or None if not found.

    No uniqueness on issuer: one tenant may register two apps against the
    same issuer, so this returns the first match (used for discovery lookups).
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_connections
        where issuer = :issuer
        order by created_at asc
        limit 1
        """,
        {"issuer": issuer},
    )


def create_connection(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    provider_type: str,
    issuer: str,
    created_by: str,
    discovery_url: str | None = None,
    authorization_endpoint: str | None = None,
    token_endpoint: str | None = None,
    userinfo_endpoint: str | None = None,
    jwks_uri: str | None = None,
    client_id: str | None = None,
    client_secret_enc: str | None = None,
    scopes: str | None = None,
    claim_mapping: dict[str, str] | None = None,
    correlation_claim: str = "sub",
    group_claim_source: str | None = None,
    hosted_domain: str | None = None,
    entra_tenant_id: str | None = None,
    is_enabled: bool = False,
    is_default: bool = False,
    require_platform_mfa: bool = False,
    jit_provisioning: bool = False,
    allow_email_linking: bool = False,
) -> dict | None:
    """Create a new OIDC connection.

    Returns the created row, or None if the insert failed.
    """
    if claim_mapping is None:
        claim_mapping = {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
        }

    return fetchone(
        tenant_id,
        f"""
        insert into oidc_idp_connections (
            tenant_id, name, provider_type, issuer, discovery_url,
            authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
            client_id, client_secret_enc, scopes, claim_mapping,
            correlation_claim, group_claim_source, hosted_domain,
            entra_tenant_id, is_enabled, is_default, require_platform_mfa,
            jit_provisioning, allow_email_linking, created_by
        )
        values (
            :tenant_id, :name, :provider_type, :issuer, :discovery_url,
            :authorization_endpoint, :token_endpoint, :userinfo_endpoint, :jwks_uri,
            :client_id, :client_secret_enc, :scopes, :claim_mapping,
            :correlation_claim, :group_claim_source, :hosted_domain,
            :entra_tenant_id, :is_enabled, :is_default, :require_platform_mfa,
            :jit_provisioning, :allow_email_linking, :created_by
        )
        returning {_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "name": name,
            "provider_type": provider_type,
            "issuer": issuer,
            "discovery_url": discovery_url,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
            "jwks_uri": jwks_uri,
            "client_id": client_id,
            "client_secret_enc": client_secret_enc,
            "scopes": scopes,
            "claim_mapping": json.dumps(claim_mapping),
            "correlation_claim": correlation_claim,
            "group_claim_source": group_claim_source,
            "hosted_domain": hosted_domain,
            "entra_tenant_id": entra_tenant_id,
            "is_enabled": is_enabled,
            "is_default": is_default,
            "require_platform_mfa": require_platform_mfa,
            "jit_provisioning": jit_provisioning,
            "allow_email_linking": allow_email_linking,
            "created_by": created_by,
        },
    )


def update_connection(
    tenant_id: TenantArg,
    connection_id: str,
    **kwargs: Any,
) -> dict | None:
    """Update an OIDC connection.

    Accepts any combination of whitelisted fields. Field names are validated
    against ``allowed_fields`` before being used in SQL; values are always
    parameterized. ``claim_mapping`` is JSON-serialized before update.

    Returns the updated row, or None if not found.
    """
    allowed_fields = {
        "name",
        "issuer",
        "discovery_url",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "discovery_fetched_at",
        "discovery_error",
        "client_id",
        "client_secret_enc",
        "scopes",
        "claim_mapping",
        "correlation_claim",
        "group_claim_source",
        "hosted_domain",
        "entra_tenant_id",
        "require_platform_mfa",
        "jit_provisioning",
        "allow_email_linking",
    }

    # Fields that can be explicitly set to NULL (cleared).
    nullable_fields = {
        "discovery_url",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "discovery_fetched_at",
        "discovery_error",
        "client_id",
        "client_secret_enc",
        "scopes",
        "group_claim_source",
        "hosted_domain",
        "entra_tenant_id",
    }

    set_clauses = []
    params: dict[str, Any] = {"connection_id": connection_id}

    for field, value in kwargs.items():
        if field not in allowed_fields:
            continue
        if value is None and field not in nullable_fields:
            continue
        if field == "claim_mapping" and value is not None:
            value = json.dumps(value)
        set_clauses.append(f"{field} = :{field}")
        params[field] = value

    if not set_clauses:
        return get_connection(tenant_id, connection_id)

    query = f"""
        update oidc_idp_connections
        set {", ".join(set_clauses)}
        where id = :connection_id
        returning {_COLUMNS}
    """

    return fetchone(tenant_id, query, params)


def set_connection_enabled(
    tenant_id: TenantArg,
    connection_id: str,
    is_enabled: bool,
) -> dict | None:
    """Enable or disable an OIDC connection."""
    return fetchone(
        tenant_id,
        f"""
        update oidc_idp_connections
        set is_enabled = :is_enabled
        where id = :connection_id
        returning {_COLUMNS}
        """,
        {"connection_id": connection_id, "is_enabled": is_enabled},
    )


def set_connection_default(
    tenant_id: TenantArg,
    connection_id: str,
) -> dict | None:
    """Set an OIDC connection as the default for the tenant.

    The database trigger unsets other defaults.
    """
    return fetchone(
        tenant_id,
        f"""
        update oidc_idp_connections
        set is_default = true
        where id = :connection_id
        returning {_COLUMNS}
        """,
        {"connection_id": connection_id},
    )


def delete_connection(tenant_id: TenantArg, connection_id: str) -> int:
    """Delete an OIDC connection. Returns the number of rows deleted."""
    return execute(
        tenant_id,
        "delete from oidc_idp_connections where id = :connection_id",
        {"connection_id": connection_id},
    )


def get_enabled_connections(tenant_id: TenantArg) -> list[dict]:
    """Get all enabled OIDC connections for a tenant (for login display)."""
    return fetchall(
        tenant_id,
        """
        select id, name, provider_type
        from oidc_idp_connections
        where is_enabled = true
        order by is_default desc, name asc
        """,
        {},
    )


def get_default_connection(tenant_id: TenantArg) -> dict | None:
    """Get the default enabled OIDC connection for a tenant, or None."""
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from oidc_idp_connections
        where is_default = true and is_enabled = true
        """,
        {},
    )
