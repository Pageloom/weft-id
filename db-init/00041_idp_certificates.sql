-- ============================================================================
-- IdP Certificates
--
-- Stores multiple signing certificates per IdP to support certificate
-- rotation. During rotation, the IdP may sign with either the old or new
-- certificate. WeftId validates against all certificates in the table.
-- Certificates are managed exclusively through metadata sync.
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- TABLE: idp_certificates
-- Multiple signing certificates per SAML identity provider
-- ============================================================================

CREATE TABLE IF NOT EXISTS idp_certificates
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idp_id          UUID        NOT NULL,
    tenant_id       UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    certificate_pem TEXT        NOT NULL,
    fingerprint     TEXT        NOT NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_idp_cert_idp
        FOREIGN KEY (idp_id)
            REFERENCES saml_identity_providers (id)
            ON DELETE CASCADE,

    CONSTRAINT fk_idp_cert_tenant
        FOREIGN KEY (tenant_id)
            REFERENCES tenants (id)
            ON DELETE CASCADE,

    CONSTRAINT uq_idp_cert_fingerprint
        UNIQUE (idp_id, fingerprint)
);

COMMENT ON TABLE idp_certificates IS
    'Multiple signing certificates per IdP for rotation support. All certs are tried during SAML validation.';

COMMENT ON COLUMN idp_certificates.fingerprint IS
    'SHA-256 fingerprint of the certificate, colon-separated hex. Used for deduplication.';


-- ============================================================================
-- INDEXES
-- ============================================================================

-- Certificates for a given IdP (primary query path during SAML validation)
CREATE INDEX IF NOT EXISTS idx_idp_certificates_idp
    ON idp_certificates (idp_id);

-- Tenant lookup
CREATE INDEX IF NOT EXISTS idx_idp_certificates_tenant
    ON idp_certificates (tenant_id);


-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE idp_certificates TO appuser;


-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE idp_certificates ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'idp_certificates'
                         AND policyname = 'idp_certificates_tenant_isolation') THEN
            CREATE POLICY idp_certificates_tenant_isolation ON idp_certificates
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;


-- ============================================================================
-- DATA MIGRATION: Copy existing IdP certificates
-- ============================================================================
-- Copy the certificate_pem from each saml_identity_providers row into
-- idp_certificates. Use an empty fingerprint as placeholder; the app
-- backfills the real SHA-256 fingerprint on first access.

INSERT INTO idp_certificates (idp_id, tenant_id, certificate_pem, fingerprint)
SELECT id, tenant_id, certificate_pem, ''
FROM saml_identity_providers
WHERE certificate_pem IS NOT NULL
  AND certificate_pem != ''
ON CONFLICT DO NOTHING;
