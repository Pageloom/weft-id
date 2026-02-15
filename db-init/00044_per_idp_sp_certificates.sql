-- Per-IdP SP certificates and two-step IdP creation
--
-- Each IdP now gets its own SP certificate, EntityID, and metadata URL.
-- IdP creation becomes two-step: name first, trust establishment later.

SET LOCAL ROLE appowner;

-- =============================================================================
-- 1. Per-IdP SP Certificates table
-- =============================================================================

CREATE TABLE IF NOT EXISTS saml_idp_sp_certificates (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_id      uuid NOT NULL UNIQUE REFERENCES saml_identity_providers(id) ON DELETE CASCADE,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    certificate_pem         text NOT NULL,
    private_key_pem_enc     text NOT NULL,
    expires_at              timestamptz NOT NULL,
    created_by              uuid NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    -- Rotation support (mirrors sp_signing_certificates pattern)
    previous_certificate_pem        text,
    previous_private_key_pem_enc    text,
    previous_expires_at             timestamptz,
    rotation_grace_period_ends_at   timestamptz
);

ALTER TABLE saml_idp_sp_certificates ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON saml_idp_sp_certificates
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE INDEX IF NOT EXISTS idx_saml_idp_sp_certificates_tenant
    ON saml_idp_sp_certificates(tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON saml_idp_sp_certificates TO appuser;

-- =============================================================================
-- 2. Alter saml_identity_providers for two-step creation
-- =============================================================================

-- Allow NULL for entity_id, sso_url, certificate_pem (pending IdPs)
ALTER TABLE saml_identity_providers
    ALTER COLUMN entity_id DROP NOT NULL;

ALTER TABLE saml_identity_providers
    ALTER COLUMN sso_url DROP NOT NULL;

ALTER TABLE saml_identity_providers
    ALTER COLUMN certificate_pem DROP NOT NULL;

-- Add trust_established flag
ALTER TABLE saml_identity_providers
    ADD COLUMN IF NOT EXISTS trust_established boolean NOT NULL DEFAULT false;

-- Backfill: existing IdPs with entity_id are already trusted
UPDATE saml_identity_providers
    SET trust_established = true
    WHERE entity_id IS NOT NULL;
