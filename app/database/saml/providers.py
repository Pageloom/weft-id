"""SAML identity provider database operations."""

import json
from typing import Any

from database._core import TenantArg, execute, fetchall, fetchone


def list_identity_providers(tenant_id: TenantArg) -> list[dict]:
    """
    List all identity providers for a tenant.

    Returns:
        List of IdP dicts ordered by created_at desc
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
               certificate_pem, metadata_url, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               created_by, created_at, updated_at
        from saml_identity_providers
        order by created_at desc
        """,
        {},
    )


def get_identity_provider(tenant_id: TenantArg, idp_id: str) -> dict | None:
    """
    Get an identity provider by ID.

    Returns:
        IdP dict or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
               certificate_pem, metadata_url, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               created_by, created_at, updated_at
        from saml_identity_providers
        where id = :idp_id
        """,
        {"idp_id": idp_id},
    )


def get_identity_provider_by_entity_id(tenant_id: TenantArg, entity_id: str) -> dict | None:
    """
    Get an identity provider by entity ID.

    Returns:
        IdP dict or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
               certificate_pem, metadata_url, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               created_by, created_at, updated_at
        from saml_identity_providers
        where entity_id = :entity_id
        """,
        {"entity_id": entity_id},
    )


def create_identity_provider(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    provider_type: str,
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    sp_entity_id: str,
    created_by: str,
    slo_url: str | None = None,
    metadata_url: str | None = None,
    attribute_mapping: dict[str, str] | None = None,
    is_enabled: bool = False,
    is_default: bool = False,
    require_platform_mfa: bool = False,
    jit_provisioning: bool = False,
) -> dict | None:
    """
    Create a new identity provider.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        name: Display name for the IdP
        provider_type: Type (okta, azure_ad, google, generic)
        entity_id: IdP entity ID from metadata
        sso_url: IdP SSO endpoint URL
        certificate_pem: IdP signing certificate (PEM)
        sp_entity_id: Auto-generated SP entity ID
        created_by: User ID who created the IdP
        slo_url: Optional IdP SLO URL
        metadata_url: Optional IdP metadata URL for auto-refresh
        attribute_mapping: SAML attribute mapping
        is_enabled: Whether IdP is enabled
        is_default: Whether this is the default IdP
        require_platform_mfa: Whether to require platform MFA after SAML
        jit_provisioning: Whether to enable JIT user provisioning

    Returns:
        Dict with created IdP details
    """
    if attribute_mapping is None:
        attribute_mapping = {"email": "email", "first_name": "firstName", "last_name": "lastName"}

    return fetchone(
        tenant_id,
        """
        insert into saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url, slo_url,
            certificate_pem, metadata_url, sp_entity_id,
            attribute_mapping, is_enabled, is_default, require_platform_mfa,
            jit_provisioning, created_by
        )
        values (
            :tenant_id, :name, :provider_type, :entity_id, :sso_url, :slo_url,
            :certificate_pem, :metadata_url, :sp_entity_id,
            :attribute_mapping, :is_enabled, :is_default, :require_platform_mfa,
            :jit_provisioning, :created_by
        )
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  created_by, created_at, updated_at
        """,
        {
            "tenant_id": tenant_id_value,
            "name": name,
            "provider_type": provider_type,
            "entity_id": entity_id,
            "sso_url": sso_url,
            "slo_url": slo_url,
            "certificate_pem": certificate_pem,
            "metadata_url": metadata_url,
            "sp_entity_id": sp_entity_id,
            "attribute_mapping": json.dumps(attribute_mapping),
            "is_enabled": is_enabled,
            "is_default": is_default,
            "require_platform_mfa": require_platform_mfa,
            "jit_provisioning": jit_provisioning,
            "created_by": created_by,
        },
    )


def update_identity_provider(
    tenant_id: TenantArg,
    idp_id: str,
    **kwargs: Any,
) -> dict | None:
    """
    Update an identity provider.

    Accepts any combination of:
        name, sso_url, slo_url, certificate_pem, metadata_url,
        attribute_mapping, require_platform_mfa, jit_provisioning

    Returns:
        Dict with updated IdP details
    """
    # SECURITY: Dynamic SET clause construction with field name validation.
    #
    # This function updates only whitelisted fields (lines 283-291).
    # Field names are validated against allowed_fields before being used in SQL.
    # Values are ALWAYS parameterized (e.g., :name, :sso_url) - never interpolated.
    #
    # Example: If field="name", SQL becomes: "name = :name"
    # - "name" comes from allowed_fields whitelist (safe)
    # - :name is a parameterized value handled by psycopg (safe)
    #
    # Attack scenarios prevented:
    # - f"{malicious_field} = :value" -> blocked by whitelist check (line 296)
    # - f"name = {malicious_value}" -> impossible, we use :name parameter
    #
    # DO NOT add fields to allowed_fields without security review.
    # DO NOT change parameterization pattern (line 299).

    # Build SET clause dynamically from provided kwargs
    allowed_fields = {
        "name",
        "sso_url",
        "slo_url",
        "certificate_pem",
        "metadata_url",
        "attribute_mapping",
        "require_platform_mfa",
        "jit_provisioning",
    }

    set_clauses = []
    params: dict[str, Any] = {"idp_id": idp_id}

    for field, value in kwargs.items():
        if field in allowed_fields and value is not None:
            if field == "attribute_mapping":
                value = json.dumps(value)
            set_clauses.append(f"{field} = :{field}")
            params[field] = value

    if not set_clauses:
        # Nothing to update, just return current state
        return get_identity_provider(tenant_id, idp_id)

    query = f"""
        update saml_identity_providers
        set {", ".join(set_clauses)}
        where id = :idp_id
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  created_by, created_at, updated_at
    """

    return fetchone(tenant_id, query, params)


def update_idp_metadata_fields(
    tenant_id: TenantArg,
    idp_id: str,
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
) -> dict | None:
    """
    Update IdP fields from metadata refresh.

    Updates entity_id, sso_url, slo_url, certificate_pem and clears fetch error.

    Returns:
        Dict with updated IdP details
    """
    return fetchone(
        tenant_id,
        """
        update saml_identity_providers
        set entity_id = :entity_id,
            sso_url = :sso_url,
            slo_url = :slo_url,
            certificate_pem = :certificate_pem,
            metadata_last_fetched_at = now(),
            metadata_fetch_error = null
        where id = :idp_id
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  created_by, created_at, updated_at
        """,
        {
            "idp_id": idp_id,
            "entity_id": entity_id,
            "sso_url": sso_url,
            "slo_url": slo_url,
            "certificate_pem": certificate_pem,
        },
    )


def set_idp_metadata_error(
    tenant_id: TenantArg,
    idp_id: str,
    error: str,
) -> int:
    """
    Set metadata fetch error for an IdP.

    Returns:
        Number of rows updated
    """
    return execute(
        tenant_id,
        """
        update saml_identity_providers
        set metadata_fetch_error = :error
        where id = :idp_id
        """,
        {"idp_id": idp_id, "error": error},
    )


def set_idp_enabled(
    tenant_id: TenantArg,
    idp_id: str,
    is_enabled: bool,
) -> dict | None:
    """
    Enable or disable an IdP.

    Returns:
        Dict with updated IdP details
    """
    return fetchone(
        tenant_id,
        """
        update saml_identity_providers
        set is_enabled = :is_enabled
        where id = :idp_id
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  created_by, created_at, updated_at
        """,
        {"idp_id": idp_id, "is_enabled": is_enabled},
    )


def set_idp_default(
    tenant_id: TenantArg,
    idp_id: str,
) -> dict | None:
    """
    Set an IdP as the default for the tenant.

    The database trigger will unset other defaults.

    Returns:
        Dict with updated IdP details
    """
    return fetchone(
        tenant_id,
        """
        update saml_identity_providers
        set is_default = true
        where id = :idp_id
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  created_by, created_at, updated_at
        """,
        {"idp_id": idp_id},
    )


def delete_identity_provider(tenant_id: TenantArg, idp_id: str) -> int:
    """
    Delete an identity provider.

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from saml_identity_providers where id = :idp_id",
        {"idp_id": idp_id},
    )


# ============================================================================
# Query Functions for Login Flow
# ============================================================================


def get_enabled_identity_providers(tenant_id: TenantArg) -> list[dict]:
    """
    Get all enabled identity providers for a tenant (for login page).

    Returns:
        List of enabled IdP dicts with minimal fields for login display
    """
    return fetchall(
        tenant_id,
        """
        select id, name, provider_type
        from saml_identity_providers
        where is_enabled = true
        order by is_default desc, name asc
        """,
        {},
    )


def get_default_identity_provider(tenant_id: TenantArg) -> dict | None:
    """
    Get the default identity provider for a tenant.

    Returns:
        IdP dict or None if no default configured
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
               certificate_pem, metadata_url, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               created_by, created_at, updated_at
        from saml_identity_providers
        where is_default = true and is_enabled = true
        """,
        {},
    )


def get_user_assigned_idp(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get the IdP assigned to a specific user (if any).

    Returns:
        IdP dict or None if user has no assigned IdP
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
        from users u
        join saml_identity_providers idp on u.saml_idp_id = idp.id
        where u.id = :user_id
        """,
        {"user_id": user_id},
    )


def set_user_idp(tenant_id: TenantArg, user_id: str, idp_id: str) -> int:
    """
    Set the SAML IdP for a user (used for JIT-provisioned users).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to update
        idp_id: IdP ID to assign to the user

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update users
        set saml_idp_id = :idp_id
        where id = :user_id
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )


# ============================================================================
# Background Job Functions (No RLS)
# ============================================================================


def get_idps_with_metadata_url() -> list[dict]:
    """
    Get all IdPs that have a metadata URL configured (across all tenants).

    Used by the background refresh job.
    Does not use RLS (called without tenant context).

    Returns:
        List of IdP dicts with tenant_id for scoping
    """
    from psycopg.rows import dict_row

    from database._core import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select id, tenant_id, name, metadata_url
                from saml_identity_providers
                where metadata_url is not null
            """
            )
            return list(cur.fetchall())
