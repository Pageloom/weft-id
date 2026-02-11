-- ============================================================================
-- Per-SP Signing Certificates
--
-- This migration creates the sp_signing_certificates table for SAML IdP
-- Phase 2. Each downstream Service Provider gets its own signing certificate,
-- isolating rotation and compromise blast radius.
--
-- The existing saml_sp_certificates table is for the "platform as SP" use
-- case (upstream IdPs). This new table is for the "platform as IdP" use
-- case (downstream SPs).
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- TABLE: sp_signing_certificates
-- Per-SP signing certificates for SAML IdP assertions
-- ============================================================================

CREATE TABLE IF NOT EXISTS sp_signing_certificates
(
    id                              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sp_id                           UUID        NOT NULL UNIQUE,
    tenant_id                       UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    certificate_pem                 TEXT        NOT NULL,
    private_key_pem_enc             TEXT        NOT NULL,
    expires_at                      TIMESTAMPTZ NOT NULL,
    created_by                      UUID        NOT NULL,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Rotation support (same pattern as saml_sp_certificates)
    previous_certificate_pem        TEXT,
    previous_private_key_pem_enc    TEXT,
    previous_expires_at             TIMESTAMPTZ,
    rotation_grace_period_ends_at   TIMESTAMPTZ,

    CONSTRAINT fk_sp_signing_cert_sp
        FOREIGN KEY (sp_id)
            REFERENCES service_providers (id)
            ON DELETE CASCADE,

    CONSTRAINT fk_sp_signing_cert_tenant
        FOREIGN KEY (tenant_id)
            REFERENCES tenants (id)
            ON DELETE CASCADE
);

COMMENT ON TABLE sp_signing_certificates IS
    'Per-SP signing certificates for SAML IdP assertions. Each downstream SP gets its own cert to isolate rotation blast radius.';

COMMENT ON COLUMN sp_signing_certificates.sp_id IS
    'Service provider this certificate belongs to. One certificate per SP.';

COMMENT ON COLUMN sp_signing_certificates.private_key_pem_enc IS
    'Fernet-encrypted PEM-encoded RSA private key.';

COMMENT ON COLUMN sp_signing_certificates.previous_certificate_pem IS
    'Previous certificate kept during rotation grace period. Both certs are valid.';

COMMENT ON COLUMN sp_signing_certificates.rotation_grace_period_ends_at IS
    'When the grace period ends. After this, previous cert can be cleared.';


-- ============================================================================
-- INDEXES
-- ============================================================================

-- Tenant lookup
CREATE INDEX IF NOT EXISTS idx_sp_signing_certificates_tenant
    ON sp_signing_certificates (tenant_id);

-- SP lookup (covered by UNIQUE constraint, explicit for clarity)
CREATE INDEX IF NOT EXISTS idx_sp_signing_certificates_sp_id
    ON sp_signing_certificates (sp_id);


-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE sp_signing_certificates TO appuser;


-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE sp_signing_certificates ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'sp_signing_certificates'
                         AND policyname = 'sp_signing_certificates_tenant_isolation') THEN
            CREATE POLICY sp_signing_certificates_tenant_isolation ON sp_signing_certificates
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;
