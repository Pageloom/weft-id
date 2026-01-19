-- ============================================================================
-- SAML Debug Storage
--
-- Stores failed SAML authentication attempts for debugging.
-- Entries are automatically cleaned up after 24 hours.
--
-- This table helps admins troubleshoot SAML configuration issues by:
--   - Storing the raw SAML response XML for inspection
--   - Recording error types and details
--   - Linking to the IdP that caused the failure
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- CREATE TABLE: saml_debug_entries
-- ============================================================================

CREATE TABLE IF NOT EXISTS saml_debug_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),

    -- IdP reference (may be NULL if we couldn't determine the IdP)
    idp_id UUID REFERENCES saml_identity_providers(id) ON DELETE SET NULL,
    idp_name TEXT,

    -- Error information
    error_type TEXT NOT NULL,
    error_detail TEXT,

    -- Raw SAML response (base64 encoded)
    saml_response_b64 TEXT,

    -- Decoded XML (stored for convenience, may be NULL if decoding failed)
    saml_response_xml TEXT,

    -- Request metadata
    request_ip TEXT,
    user_agent TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Foreign key index
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Index for tenant lookups
CREATE INDEX IF NOT EXISTS idx_saml_debug_entries_tenant
    ON saml_debug_entries(tenant_id, created_at DESC);

-- Index for automatic cleanup (entries older than 24 hours)
CREATE INDEX IF NOT EXISTS idx_saml_debug_entries_cleanup
    ON saml_debug_entries(created_at);

COMMENT ON TABLE saml_debug_entries IS
    'Stores failed SAML authentication attempts for debugging. Auto-cleaned after 24h.';

-- ============================================================================
-- PERMISSIONS
-- ============================================================================

GRANT SELECT, INSERT, DELETE ON saml_debug_entries TO app;
