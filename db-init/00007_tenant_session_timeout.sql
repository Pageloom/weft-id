-- ============================================================================
-- Tenant Session Timeout Configuration
--
-- This migration adds support for tenants to configure maximum session
-- timeout/duration for their users. Only super admins can configure this.
--
-- Changes:
--   1) New table: tenant_security_settings
--      - Stores session_timeout_seconds (NULL = indefinite)
--      - Stores persistent_sessions (true = sessions survive browser close)
--      - RLS enabled for tenant isolation
--      - One row per tenant (enforced by unique constraint)
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_security_settings
(
    id                      UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL UNIQUE REFERENCES tenants (id) ON DELETE CASCADE,
    session_timeout_seconds INTEGER              DEFAULT NULL CHECK (session_timeout_seconds IS NULL OR session_timeout_seconds > 0),
    persistent_sessions     BOOLEAN     NOT NULL DEFAULT true,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by              UUID,

    -- Foreign key to users
    CONSTRAINT fk_updated_by_user
        FOREIGN KEY (updated_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL
);

COMMENT ON TABLE tenant_security_settings IS
    'Security configuration settings for each tenant. Only super admins can manage. RLS enforces tenant isolation.';

COMMENT ON COLUMN tenant_security_settings.session_timeout_seconds IS
    'Maximum session duration in seconds. NULL means indefinite (no timeout).';

COMMENT ON COLUMN tenant_security_settings.persistent_sessions IS
    'Whether sessions should persist after browser is closed. Default is true (sessions persist).';

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_tenant_security_settings_tenant
    ON tenant_security_settings (tenant_id);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_security_settings TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE tenant_security_settings ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'tenant_security_settings'
                         AND policyname = 'tenant_security_settings_isolation') THEN
            CREATE POLICY tenant_security_settings_isolation ON tenant_security_settings
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

COMMIT;
