"""SAML identity provider database operations."""

import json
from datetime import UTC, datetime
from typing import Any

from database._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


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
               certificate_pem, metadata_url, metadata_xml, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               trust_established, created_by, created_at, updated_at
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
               certificate_pem, metadata_url, metadata_xml, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               trust_established, created_by, created_at, updated_at
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
               certificate_pem, metadata_url, metadata_xml, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               trust_established, created_by, created_at, updated_at
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
    sp_entity_id: str,
    created_by: str,
    entity_id: str | None = None,
    sso_url: str | None = None,
    certificate_pem: str | None = None,
    slo_url: str | None = None,
    metadata_url: str | None = None,
    metadata_xml: str | None = None,
    attribute_mapping: dict[str, str] | None = None,
    is_enabled: bool = False,
    is_default: bool = False,
    require_platform_mfa: bool = False,
    jit_provisioning: bool = False,
    trust_established: bool = False,
) -> dict | None:
    """
    Create a new identity provider.

    For two-step creation, entity_id/sso_url/certificate_pem may be None
    (pending IdP). Trust is established later.

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
            certificate_pem, metadata_url, metadata_xml, metadata_last_fetched_at,
            sp_entity_id, attribute_mapping, is_enabled, is_default,
            require_platform_mfa, jit_provisioning, trust_established, created_by
        )
        values (
            :tenant_id, :name, :provider_type, :entity_id, :sso_url, :slo_url,
            :certificate_pem, :metadata_url, :metadata_xml, :metadata_last_fetched_at,
            :sp_entity_id, :attribute_mapping, :is_enabled, :is_default,
            :require_platform_mfa, :jit_provisioning, :trust_established, :created_by
        )
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  trust_established, created_by, created_at, updated_at
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
            "metadata_xml": metadata_xml,
            "metadata_last_fetched_at": datetime.now(UTC) if metadata_url else None,
            "sp_entity_id": sp_entity_id,
            "attribute_mapping": json.dumps(attribute_mapping),
            "is_enabled": is_enabled,
            "is_default": is_default,
            "require_platform_mfa": require_platform_mfa,
            "jit_provisioning": jit_provisioning,
            "trust_established": trust_established,
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
        "sp_entity_id",
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
                  trust_established, created_by, created_at, updated_at
    """

    return fetchone(tenant_id, query, params)


def update_idp_metadata_fields(
    tenant_id: TenantArg,
    idp_id: str,
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
    metadata_xml: str | None = None,
) -> dict | None:
    """
    Update IdP fields from metadata refresh.

    Updates entity_id, sso_url, slo_url, certificate_pem, metadata_xml
    and clears fetch error.

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
            metadata_xml = :metadata_xml,
            metadata_last_fetched_at = now(),
            metadata_fetch_error = null
        where id = :idp_id
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  trust_established, created_by, created_at, updated_at
        """,
        {
            "idp_id": idp_id,
            "entity_id": entity_id,
            "sso_url": sso_url,
            "slo_url": slo_url,
            "certificate_pem": certificate_pem,
            "metadata_xml": metadata_xml,
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
                  trust_established, created_by, created_at, updated_at
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
                  trust_established, created_by, created_at, updated_at
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


def set_idp_trust_established(
    tenant_id: TenantArg,
    idp_id: str,
    entity_id: str,
    sso_url: str,
    certificate_pem: str,
    slo_url: str | None = None,
    metadata_url: str | None = None,
    metadata_xml: str | None = None,
) -> dict | None:
    """
    Establish trust on a pending IdP by setting its IdP-side fields.

    Sets trust_established=true and populates entity_id, sso_url, certificate_pem
    (plus optional slo_url, metadata_url, metadata_xml).

    Returns:
        Dict with updated IdP details, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        update saml_identity_providers
        set entity_id = :entity_id,
            sso_url = :sso_url,
            slo_url = :slo_url,
            certificate_pem = :certificate_pem,
            metadata_url = :metadata_url,
            metadata_xml = :metadata_xml,
            metadata_last_fetched_at = case when :has_metadata_url then now() else null end,
            trust_established = true
        where id = :idp_id
        returning id, tenant_id, name, provider_type, entity_id, sso_url, slo_url,
                  certificate_pem, metadata_url, metadata_last_fetched_at,
                  metadata_fetch_error, sp_entity_id, attribute_mapping,
                  is_enabled, is_default, require_platform_mfa, jit_provisioning,
                  trust_established, created_by, created_at, updated_at
        """,
        {
            "idp_id": idp_id,
            "entity_id": entity_id,
            "sso_url": sso_url,
            "slo_url": slo_url,
            "certificate_pem": certificate_pem,
            "metadata_url": metadata_url,
            "metadata_xml": metadata_xml,
            "has_metadata_url": metadata_url is not None,
        },
    )


# ============================================================================
# Query Functions for Login Flow
# ============================================================================


def get_public_idp_info(tenant_id: TenantArg, idp_id: str) -> dict | None:
    """
    Get minimal IdP info for the public trust page.

    Returns None if not found, or if both disabled and trust already established
    (i.e. intentionally disabled by admin). Pending IdPs (trust_established=false)
    are always visible so external admins can see SP metadata during setup.
    """
    return fetchone(
        tenant_id,
        """
        select id, name, provider_type, sp_entity_id, attribute_mapping,
               is_enabled, jit_provisioning, trust_established
        from saml_identity_providers
        where id = :idp_id and (is_enabled = true or trust_established = false)
        """,
        {"idp_id": idp_id},
    )


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
               certificate_pem, metadata_url, metadata_xml, metadata_last_fetched_at,
               metadata_fetch_error, sp_entity_id, attribute_mapping,
               is_enabled, is_default, require_platform_mfa, jit_provisioning,
               trust_established, created_by, created_at, updated_at
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
               idp.metadata_xml, idp.metadata_last_fetched_at, idp.metadata_fetch_error,
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
    Uses UNSCOPED to bypass RLS (system task).

    Returns:
        List of IdP dicts with tenant_id for scoping
    """
    return fetchall(
        UNSCOPED,
        """
        select id, tenant_id, name, metadata_url
        from saml_identity_providers
        where metadata_url is not null
        """,
    )
