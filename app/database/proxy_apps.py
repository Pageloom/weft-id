"""Proxy app database operations.

A proxy app is an HTTP application behind a protected domain, gated by WeftID's
forward-auth authority. public_paths and header_config are stored as JSONB
(mirroring service_providers.attribute_mapping); validation lives in the service
layer. All queries are RLS-scoped by tenant.
"""

import json

from database._core import TenantArg, execute, fetchall, fetchone

_COLUMNS = """id, tenant_id, protected_domain_id, name, description,
              external_url, public_paths, header_config, available_to_all,
              enabled, created_by, created_at, updated_at"""


def list_proxy_apps(tenant_id: TenantArg) -> list[dict]:
    """List all proxy apps for a tenant.

    Returns:
        List of proxy-app dicts ordered by created_at desc.
    """
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from proxy_apps
        order by created_at desc
        """,
        {},
    )


def list_proxy_apps_for_domain(tenant_id: TenantArg, protected_domain_id: str) -> list[dict]:
    """List proxy apps belonging to a protected domain.

    Returns:
        List of proxy-app dicts ordered by name.
    """
    return fetchall(
        tenant_id,
        f"""
        select {_COLUMNS}
        from proxy_apps
        where protected_domain_id = :protected_domain_id
        order by name
        """,
        {"protected_domain_id": protected_domain_id},
    )


def get_proxy_app(tenant_id: TenantArg, proxy_app_id: str) -> dict | None:
    """Get a proxy app by ID.

    Returns:
        Proxy-app dict, or None if not found.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_COLUMNS}
        from proxy_apps
        where id = :proxy_app_id
        """,
        {"proxy_app_id": proxy_app_id},
    )


def create_proxy_app(
    tenant_id: TenantArg,
    tenant_id_value: str,
    protected_domain_id: str,
    name: str,
    external_url: str,
    created_by: str,
    description: str | None = None,
    public_paths: list | None = None,
    header_config: dict | None = None,
    available_to_all: bool = False,
    enabled: bool = True,
) -> dict | None:
    """Create a proxy app.

    Returns:
        Created proxy-app dict, or None on failure.
    """
    return fetchone(
        tenant_id,
        f"""
        insert into proxy_apps (
            tenant_id, protected_domain_id, name, description, external_url,
            public_paths, header_config, available_to_all, enabled, created_by
        )
        values (
            :tenant_id, :protected_domain_id, :name, :description, :external_url,
            :public_paths, :header_config, :available_to_all, :enabled, :created_by
        )
        returning {_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "protected_domain_id": protected_domain_id,
            "name": name,
            "description": description,
            "external_url": external_url,
            "public_paths": json.dumps(public_paths if public_paths is not None else []),
            "header_config": json.dumps(header_config if header_config is not None else {}),
            "available_to_all": available_to_all,
            "enabled": enabled,
            "created_by": created_by,
        },
    )


def update_proxy_app(
    tenant_id: TenantArg,
    proxy_app_id: str,
    **fields: object,
) -> dict | None:
    """Update a proxy app's mutable fields.

    Only the provided keyword arguments are updated. Allowed keys: name,
    description, external_url, public_paths, header_config, available_to_all,
    enabled. JSONB fields (public_paths, header_config) are serialized here.

    Returns:
        Updated proxy-app dict, or None if not found.
    """
    allowed = {
        "name",
        "description",
        "external_url",
        "public_paths",
        "header_config",
        "available_to_all",
        "enabled",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_proxy_app(tenant_id, proxy_app_id)

    # JSONB fields must be serialized to a JSON string for psycopg.
    for json_field in ("public_paths", "header_config"):
        if json_field in updates:
            updates[json_field] = json.dumps(updates[json_field])

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    params: dict = {**updates, "proxy_app_id": proxy_app_id}

    return fetchone(
        tenant_id,
        f"""
        update proxy_apps
        set {set_clause}
        where id = :proxy_app_id
        returning {_COLUMNS}
        """,
        params,
    )


def delete_proxy_app(tenant_id: TenantArg, proxy_app_id: str) -> int:
    """Delete a proxy app (cascades to its group grants).

    Returns:
        Number of rows deleted (0 or 1).
    """
    return execute(
        tenant_id,
        """
        delete from proxy_apps
        where id = :proxy_app_id
        """,
        {"proxy_app_id": proxy_app_id},
    )
