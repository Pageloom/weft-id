-- ============================================================================
-- SAML Identity Providers Infrastructure
--
-- This migration implements SAML SSO infrastructure:
--   1. saml_sp_certificates - Per-tenant SP signing certificates
--   2. saml_identity_providers - IdP configurations
--   3. users.saml_idp_id - Per-user IdP override column
--
-- Design principles:
--   - One SP certificate per tenant (shared across all IdPs)
--   - Multiple IdPs can be configured per tenant
--   - Only one IdP can be the default (enforced by trigger)
--   - All tables use RLS for tenant isolation
--   - Private keys stored encrypted (Fernet)
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- TABLE: saml_sp_certificates
-- Per-tenant SP signing certificates (one per tenant)
-- ============================================================================

CREATE TABLE IF NOT EXISTS saml_sp_certificates
(
    id                  UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id           UUID UNIQUE NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    certificate_pem     TEXT        NOT NULL,
    private_key_pem_enc TEXT        NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_by          UUID        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_sp_cert_created_by_user
        FOREIGN KEY (created_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL
);

COMMENT ON TABLE saml_sp_certificates IS
    'Per-tenant SP signing certificates for SAML. One certificate per tenant.';

COMMENT ON COLUMN saml_sp_certificates.private_key_pem_enc IS
    'Fernet-encrypted PEM-encoded private key. Never stored in plaintext.';


-- ============================================================================
-- TABLE: saml_identity_providers
-- SAML Identity Provider configurations
-- ============================================================================

CREATE TABLE IF NOT EXISTS saml_identity_providers
(
    id                      UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,

    -- Basic Info
    name                    TEXT        NOT NULL,
    provider_type           TEXT        NOT NULL CHECK (provider_type IN ('okta', 'azure_ad', 'google', 'generic')),

    -- IdP Metadata
    entity_id               TEXT        NOT NULL,
    sso_url                 TEXT        NOT NULL,
    slo_url                 TEXT,
    certificate_pem         TEXT        NOT NULL,

    -- Metadata URL for auto-refresh
    metadata_url            TEXT,
    metadata_last_fetched_at TIMESTAMPTZ,
    metadata_fetch_error    TEXT,

    -- SP Metadata (auto-generated per IdP for unique ACS URLs)
    sp_entity_id            TEXT        NOT NULL,
    sp_acs_url              TEXT        NOT NULL,

    -- Attribute Mapping (JSONB)
    attribute_mapping       JSONB       NOT NULL DEFAULT '{"email": "email", "first_name": "firstName", "last_name": "lastName"}'::jsonb,

    -- Settings
    is_enabled              BOOLEAN     NOT NULL DEFAULT false,
    is_default              BOOLEAN     NOT NULL DEFAULT false,
    require_platform_mfa    BOOLEAN     NOT NULL DEFAULT false,
    jit_provisioning        BOOLEAN     NOT NULL DEFAULT false,

    -- Audit
    created_by              UUID        NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_idp_created_by_user
        FOREIGN KEY (created_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL,

    -- Unique entity_id per tenant
    CONSTRAINT uq_saml_idp_tenant_entity_id UNIQUE (tenant_id, entity_id),

    -- Unique SP ACS URL per tenant (includes IdP ID so always unique)
    CONSTRAINT uq_saml_idp_tenant_sp_acs_url UNIQUE (tenant_id, sp_acs_url)
);

COMMENT ON TABLE saml_identity_providers IS
    'SAML Identity Provider configurations. Multiple IdPs can be configured per tenant.';

COMMENT ON COLUMN saml_identity_providers.provider_type IS
    'Provider type hint for UI/defaults: okta, azure_ad, google, or generic.';

COMMENT ON COLUMN saml_identity_providers.metadata_url IS
    'Optional IdP metadata URL for automatic configuration refresh.';

COMMENT ON COLUMN saml_identity_providers.metadata_fetch_error IS
    'Last error from metadata fetch attempt. NULL if fetch was successful.';

COMMENT ON COLUMN saml_identity_providers.attribute_mapping IS
    'Maps IdP SAML attributes to platform fields. Keys: email, first_name, last_name. Values: IdP attribute names.';

COMMENT ON COLUMN saml_identity_providers.require_platform_mfa IS
    'If true, users must complete platform MFA after SAML authentication.';

COMMENT ON COLUMN saml_identity_providers.jit_provisioning IS
    'If true, automatically create users on first SAML login (Phase 2 feature).';


-- ============================================================================
-- ADD saml_idp_id to users table
-- Per-user IdP override for routing
-- ============================================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS saml_idp_id UUID REFERENCES saml_identity_providers (id) ON DELETE SET NULL;

COMMENT ON COLUMN users.saml_idp_id IS
    'Optional per-user IdP override. If set, this user must authenticate via this specific IdP.';


-- ============================================================================
-- INDEXES
-- ============================================================================

-- saml_sp_certificates: tenant lookup
CREATE INDEX IF NOT EXISTS idx_saml_sp_certificates_tenant
    ON saml_sp_certificates (tenant_id);

-- saml_identity_providers: tenant lookup
CREATE INDEX IF NOT EXISTS idx_saml_idp_tenant
    ON saml_identity_providers (tenant_id);

-- saml_identity_providers: enabled IdPs for login
CREATE INDEX IF NOT EXISTS idx_saml_idp_tenant_enabled
    ON saml_identity_providers (tenant_id)
    WHERE is_enabled = true;

-- saml_identity_providers: default IdP lookup
CREATE INDEX IF NOT EXISTS idx_saml_idp_tenant_default
    ON saml_identity_providers (tenant_id)
    WHERE is_default = true;

-- saml_identity_providers: IdPs with metadata URLs (for refresh job)
CREATE INDEX IF NOT EXISTS idx_saml_idp_with_metadata_url
    ON saml_identity_providers (id)
    WHERE metadata_url IS NOT NULL;

-- users.saml_idp_id: users with assigned IdP
CREATE INDEX IF NOT EXISTS idx_users_saml_idp
    ON users (saml_idp_id)
    WHERE saml_idp_id IS NOT NULL;


-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE saml_sp_certificates TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE saml_identity_providers TO appuser;


-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE saml_sp_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_identity_providers ENABLE ROW LEVEL SECURITY;

-- RLS policy for saml_sp_certificates
-- Uses NULLIF to handle empty string gracefully (returns NULL, which never matches tenant_id)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'saml_sp_certificates'
                         AND policyname = 'saml_sp_certificates_tenant_isolation') THEN
            CREATE POLICY saml_sp_certificates_tenant_isolation ON saml_sp_certificates
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;

-- RLS policy for saml_identity_providers
-- Uses NULLIF to handle empty string gracefully (returns NULL, which never matches tenant_id)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'saml_identity_providers'
                         AND policyname = 'saml_idp_tenant_isolation') THEN
            CREATE POLICY saml_idp_tenant_isolation ON saml_identity_providers
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;


-- ============================================================================
-- TRIGGER: Ensure only one default IdP per tenant
-- When is_default is set to true, unset any other default for the tenant
-- ============================================================================

CREATE OR REPLACE FUNCTION ensure_single_default_idp()
RETURNS TRIGGER AS $$
BEGIN
    -- If setting is_default to true, unset all other defaults for this tenant
    IF NEW.is_default = true THEN
        UPDATE saml_identity_providers
        SET is_default = false, updated_at = now()
        WHERE tenant_id = NEW.tenant_id
          AND id != NEW.id
          AND is_default = true;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_ensure_single_default_idp ON saml_identity_providers;
CREATE TRIGGER trg_ensure_single_default_idp
    BEFORE INSERT OR UPDATE OF is_default ON saml_identity_providers
    FOR EACH ROW
    WHEN (NEW.is_default = true)
    EXECUTE FUNCTION ensure_single_default_idp();


-- ============================================================================
-- TRIGGER: Auto-update updated_at timestamp
-- ============================================================================

CREATE OR REPLACE FUNCTION update_saml_idp_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_saml_idp_updated_at ON saml_identity_providers;
CREATE TRIGGER trg_saml_idp_updated_at
    BEFORE UPDATE ON saml_identity_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_saml_idp_updated_at();

COMMIT;
