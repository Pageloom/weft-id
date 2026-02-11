-- ============================================================================
-- Service Providers (Downstream SAML SPs)
--
-- This migration creates the service_providers table for SAML IdP Phase 1a.
-- Service providers are downstream applications that trust this platform
-- as their SAML Identity Provider for SSO authentication.
--
-- Design principles:
--   - Tenant-isolated via RLS (same pattern as saml_identity_providers)
--   - Entity ID unique per tenant
--   - Stores original metadata XML for reference
--   - SP signing certificate optional (not all SPs sign AuthnRequests)
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- TABLE: service_providers
-- Downstream SAML Service Provider registrations
-- ============================================================================

CREATE TABLE IF NOT EXISTS service_providers
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    name            TEXT        NOT NULL,
    entity_id       TEXT        NOT NULL,
    acs_url         TEXT        NOT NULL,
    certificate_pem TEXT,
    nameid_format   TEXT        NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    metadata_xml    TEXT,
    created_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_sp_tenant_entity_id UNIQUE (tenant_id, entity_id),

    CONSTRAINT fk_sp_created_by
        FOREIGN KEY (created_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL
);

COMMENT ON TABLE service_providers IS
    'Downstream SAML Service Provider registrations. These apps authenticate users via SSO against this platform.';

COMMENT ON COLUMN service_providers.entity_id IS
    'SAML Entity ID of the downstream SP. Unique per tenant.';

COMMENT ON COLUMN service_providers.acs_url IS
    'Assertion Consumer Service URL where SAML responses are POSTed.';

COMMENT ON COLUMN service_providers.certificate_pem IS
    'Optional SP signing certificate (PEM). Used to verify signed AuthnRequests.';

COMMENT ON COLUMN service_providers.nameid_format IS
    'NameID format for SAML assertions. Default: emailAddress.';

COMMENT ON COLUMN service_providers.metadata_xml IS
    'Original SP metadata XML, stored for reference.';


-- ============================================================================
-- INDEXES
-- ============================================================================

-- Tenant lookup
CREATE INDEX IF NOT EXISTS idx_service_providers_tenant
    ON service_providers (tenant_id);

-- Entity ID lookup within tenant (covered by unique constraint, but explicit for clarity)
CREATE INDEX IF NOT EXISTS idx_service_providers_tenant_entity_id
    ON service_providers (tenant_id, entity_id);


-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE service_providers TO appuser;


-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE service_providers ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'service_providers'
                         AND policyname = 'service_providers_tenant_isolation') THEN
            CREATE POLICY service_providers_tenant_isolation ON service_providers
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;


-- ============================================================================
-- TRIGGER: Auto-update updated_at timestamp
-- ============================================================================

CREATE OR REPLACE FUNCTION update_service_providers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_service_providers_updated_at ON service_providers;
CREATE TRIGGER trg_service_providers_updated_at
    BEFORE UPDATE ON service_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_service_providers_updated_at();
