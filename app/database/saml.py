"""SAML database operations for SP certificates and identity providers."""

import json
from typing import Any

from database._core import TenantArg, execute, fetchall, fetchone

# ============================================================================
# SP Certificate Operations
# ============================================================================


def get_sp_certificate(tenant_id: TenantArg) -> dict | None:
    """
    Get the SP certificate for a tenant.

    Returns:
        Dict with id, tenant_id, certificate_pem, private_key_pem_enc,
        expires_at, created_by, created_at, plus rotation fields:
        previous_certificate_pem, previous_private_key_pem_enc,
        previous_expires_at, rotation_grace_period_ends_at.
        Returns None if not found.
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, certificate_pem, private_key_pem_enc,
               expires_at, created_by, created_at,
               previous_certificate_pem, previous_private_key_pem_enc,
               previous_expires_at, rotation_grace_period_ends_at
        from saml_sp_certificates
        """,
        {},
    )


def create_sp_certificate(
    tenant_id: TenantArg,
    tenant_id_value: str,
    certificate_pem: str,
    private_key_pem_enc: str,
    expires_at: Any,
    created_by: str,
) -> dict | None:
    """
    Create an SP certificate for a tenant.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        certificate_pem: PEM-encoded X.509 certificate
        private_key_pem_enc: Fernet-encrypted PEM-encoded private key
        expires_at: Certificate expiry timestamp
        created_by: User ID who created the certificate

    Returns:
        Dict with created certificate details
    """
    return fetchone(
        tenant_id,
        """
        insert into saml_sp_certificates (
            tenant_id, certificate_pem, private_key_pem_enc,
            expires_at, created_by
        )
        values (
            :tenant_id, :certificate_pem, :private_key_pem_enc,
            :expires_at, :created_by
        )
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "certificate_pem": certificate_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "expires_at": expires_at,
            "created_by": created_by,
        },
    )


def update_sp_certificate(
    tenant_id: TenantArg,
    certificate_pem: str,
    private_key_pem_enc: str,
    expires_at: Any,
) -> dict | None:
    """
    Update the SP certificate for a tenant.

    Returns:
        Dict with updated certificate details
    """
    return fetchone(
        tenant_id,
        """
        update saml_sp_certificates
        set certificate_pem = :certificate_pem,
            private_key_pem_enc = :private_key_pem_enc,
            expires_at = :expires_at
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {
            "certificate_pem": certificate_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "expires_at": expires_at,
        },
    )


def rotate_sp_certificate(
    tenant_id: TenantArg,
    new_certificate_pem: str,
    new_private_key_pem_enc: str,
    new_expires_at: Any,
    previous_certificate_pem: str,
    previous_private_key_pem_enc: str,
    previous_expires_at: Any,
    rotation_grace_period_ends_at: Any,
) -> dict | None:
    """
    Rotate the SP certificate with grace period support.

    Moves the current certificate to previous_* columns and sets the new certificate.
    Both certificates remain valid during the grace period.

    Args:
        tenant_id: Tenant ID for scoping
        new_certificate_pem: The new certificate (becomes current)
        new_private_key_pem_enc: Encrypted private key for new cert
        new_expires_at: Expiry of new certificate
        previous_certificate_pem: Current certificate (becomes previous)
        previous_private_key_pem_enc: Encrypted private key of current cert
        previous_expires_at: Expiry of current/previous certificate
        rotation_grace_period_ends_at: When grace period ends

    Returns:
        Dict with updated certificate details including all rotation fields
    """
    return fetchone(
        tenant_id,
        """
        update saml_sp_certificates
        set certificate_pem = :new_certificate_pem,
            private_key_pem_enc = :new_private_key_pem_enc,
            expires_at = :new_expires_at,
            previous_certificate_pem = :previous_certificate_pem,
            previous_private_key_pem_enc = :previous_private_key_pem_enc,
            previous_expires_at = :previous_expires_at,
            rotation_grace_period_ends_at = :rotation_grace_period_ends_at
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {
            "new_certificate_pem": new_certificate_pem,
            "new_private_key_pem_enc": new_private_key_pem_enc,
            "new_expires_at": new_expires_at,
            "previous_certificate_pem": previous_certificate_pem,
            "previous_private_key_pem_enc": previous_private_key_pem_enc,
            "previous_expires_at": previous_expires_at,
            "rotation_grace_period_ends_at": rotation_grace_period_ends_at,
        },
    )


def clear_previous_certificate(tenant_id: TenantArg) -> dict | None:
    """
    Clear the previous certificate after grace period has ended.

    Returns:
        Dict with updated certificate details
    """
    return fetchone(
        tenant_id,
        """
        update saml_sp_certificates
        set previous_certificate_pem = null,
            previous_private_key_pem_enc = null,
            previous_expires_at = null,
            rotation_grace_period_ends_at = null
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {},
    )


# ============================================================================
# Identity Provider Operations
# ============================================================================


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
    # - f"{malicious_field} = :value" → blocked by whitelist check (line 296)
    # - f"name = {malicious_value}" → impossible, we use :name parameter
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
# Domain Binding Operations (Phase 3)
# ============================================================================


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


# ============================================================================
# Security Check Functions (Phase 3)
# ============================================================================


def count_users_with_idp(tenant_id: TenantArg, idp_id: str) -> int:
    """
    Count users explicitly assigned to an IdP.

    Used to check if an IdP can be safely deleted.

    Returns:
        Number of users with saml_idp_id = idp_id
    """
    result = fetchone(
        tenant_id,
        """
        select count(*) as count
        from users
        where saml_idp_id = :idp_id
        """,
        {"idp_id": idp_id},
    )
    return result["count"] if result else 0


def count_domain_bindings_for_idp(tenant_id: TenantArg, idp_id: str) -> int:
    """
    Count domains bound to an IdP.

    Used to check if an IdP can be safely deleted.

    Returns:
        Number of domains bound to this IdP
    """
    result = fetchone(
        tenant_id,
        """
        select count(*) as count
        from saml_idp_domain_bindings
        where idp_id = :idp_id
        """,
        {"idp_id": idp_id},
    )
    return result["count"] if result else 0


def count_users_without_idp_in_domain(tenant_id: TenantArg, domain: str) -> int:
    """
    Count users with emails in the domain who don't have an IdP assigned.

    These are password users in the domain who would be affected by
    a domain binding.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Email domain to check (without @)

    Returns:
        Number of users without IdP assignment
    """
    # Build the pattern in Python to avoid SQL placeholder issues with %
    pattern = f"%@{domain.lower()}"
    result = fetchone(
        tenant_id,
        """
        select count(distinct u.id) as count
        from users u
        join user_emails ue on u.id = ue.user_id
        where ue.email like :pattern
          and ue.verified_at is not null
          and u.saml_idp_id is null
        """,
        {"pattern": pattern},
    )
    return result["count"] if result else 0


def count_users_with_idp_in_domain(
    tenant_id: TenantArg,
    domain: str,
    idp_id: str,
) -> int:
    """
    Count users with emails in the domain who are assigned to a specific IdP.

    Used when rebinding a domain to show how many users will be moved.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Email domain to check (without @)
        idp_id: IdP UUID to count users for

    Returns:
        Number of users assigned to the IdP with emails in this domain
    """
    # Build the pattern in Python to avoid SQL placeholder issues with %
    pattern = f"%@{domain.lower()}"
    result = fetchone(
        tenant_id,
        """
        select count(distinct u.id) as count
        from users u
        join user_emails ue on u.id = ue.user_id
        where ue.email like :pattern
          and ue.verified_at is not null
          and u.saml_idp_id = :idp_id
        """,
        {"pattern": pattern, "idp_id": idp_id},
    )
    return result["count"] if result else 0


# ============================================================================
# Query Functions for Background Job
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

    from ._core import get_pool

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


# ============================================================================
# SAML Debug Operations (Phase 4)
# ============================================================================


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
    from psycopg.rows import dict_row

    from ._core import get_pool

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
