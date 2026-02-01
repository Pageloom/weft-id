"""SAML domain binding database operations."""

from database._core import TenantArg, execute, fetchall, fetchone


def get_domain_bindings_for_idp(tenant_id: TenantArg, idp_id: str) -> list[dict]:
    """
    Get all domain bindings for a specific IdP.

    Returns:
        List of dicts with id, domain_id, domain, created_at
    """
    return fetchall(
        tenant_id,
        """
        select db.id, db.domain_id, pd.domain, db.idp_id, db.created_at
        from saml_idp_domain_bindings db
        join tenant_privileged_domains pd on db.domain_id = pd.id
        where db.idp_id = :idp_id
        order by pd.domain
        """,
        {"idp_id": idp_id},
    )


def get_idp_for_domain(tenant_id: TenantArg, domain: str) -> dict | None:
    """
    Get the IdP bound to a specific email domain.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Email domain (without @, e.g., "company.com")

    Returns:
        IdP dict or None if domain is not bound to any IdP
    """
    return fetchone(
        tenant_id,
        """
        select idp.id, idp.tenant_id, idp.name, idp.provider_type, idp.entity_id,
               idp.sso_url, idp.slo_url, idp.certificate_pem, idp.metadata_url,
               idp.metadata_last_fetched_at, idp.metadata_fetch_error,
               idp.sp_entity_id, idp.attribute_mapping,
               idp.is_enabled, idp.is_default, idp.require_platform_mfa,
               idp.jit_provisioning, idp.created_by, idp.created_at, idp.updated_at
        from saml_idp_domain_bindings db
        join tenant_privileged_domains pd on db.domain_id = pd.id
        join saml_identity_providers idp on db.idp_id = idp.id
        where pd.domain = :domain and idp.is_enabled = true
        """,
        {"domain": domain.lower()},
    )


def bind_domain_to_idp(
    tenant_id: TenantArg,
    tenant_id_value: str,
    domain_id: str,
    idp_id: str,
    created_by: str,
) -> dict | None:
    """
    Bind a privileged domain to an IdP (upsert).

    If the domain is already bound, updates to the new IdP.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        domain_id: Privileged domain ID to bind
        idp_id: IdP ID to bind the domain to
        created_by: User ID who created the binding

    Returns:
        Dict with binding id, domain_id, idp_id, created_at
    """
    return fetchone(
        tenant_id,
        """
        insert into saml_idp_domain_bindings (tenant_id, domain_id, idp_id, created_by)
        values (:tenant_id, :domain_id, :idp_id, :created_by)
        on conflict (tenant_id, domain_id)
        do update set idp_id = :idp_id, created_by = :created_by, created_at = now()
        returning id, domain_id, idp_id, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "domain_id": domain_id,
            "idp_id": idp_id,
            "created_by": created_by,
        },
    )


def unbind_domain_from_idp(tenant_id: TenantArg, domain_id: str) -> int:
    """
    Remove a domain-to-IdP binding.

    Args:
        tenant_id: Tenant ID for scoping
        domain_id: Domain ID to unbind

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from saml_idp_domain_bindings where domain_id = :domain_id",
        {"domain_id": domain_id},
    )


def get_unbound_domains(tenant_id: TenantArg) -> list[dict]:
    """
    Get privileged domains that are not bound to any IdP.

    Returns:
        List of dicts with id, domain
    """
    return fetchall(
        tenant_id,
        """
        select pd.id, pd.domain
        from tenant_privileged_domains pd
        left join saml_idp_domain_bindings db on pd.id = db.domain_id
        where db.id is null
        order by pd.domain
        """,
        {},
    )


def list_domains_with_bindings(tenant_id: TenantArg) -> list[dict]:
    """
    Get all privileged domains with their IdP bindings (if any).

    Returns:
        List of dicts with domain info and optional IdP info
    """
    return fetchall(
        tenant_id,
        """
        select pd.id, pd.domain, pd.created_at,
               idp.id as idp_id, idp.name as idp_name
        from tenant_privileged_domains pd
        left join saml_idp_domain_bindings db on pd.id = db.domain_id
        left join saml_identity_providers idp on db.idp_id = idp.id
        order by pd.domain
        """,
        {},
    )


def get_domain_binding_by_domain_id(tenant_id: TenantArg, domain_id: str) -> dict | None:
    """
    Get the binding for a specific domain ID.

    Returns:
        Dict with binding info or None if not bound
    """
    return fetchone(
        tenant_id,
        """
        select db.id, db.domain_id, db.idp_id, pd.domain, idp.name as idp_name
        from saml_idp_domain_bindings db
        join tenant_privileged_domains pd on db.domain_id = pd.id
        join saml_identity_providers idp on db.idp_id = idp.id
        where db.domain_id = :domain_id
        """,
        {"domain_id": domain_id},
    )
