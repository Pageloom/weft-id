-- ============================================================================
-- Privileged Domains for Tenants
--
-- This migration adds support for tenants to designate privileged email
-- domains (e.g., @company.com, @company.info) that are controlled by the
-- tenant. Only super admins can manage these privileged domains.
--
-- Changes:
--   1) New table: tenant_privileged_domains
--      - Stores domain names associated with each tenant
--      - RLS enabled for tenant isolation
--      - Unique constraint on (tenant_id, domain)
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_privileged_domains
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    domain     TEXT        NOT NULL CHECK (length(domain) > 0 AND length(domain) <= 253),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID        NOT NULL,

    -- Ensure domain is unique per tenant
    UNIQUE (tenant_id, domain),

    -- Foreign key to users, but we can't enforce it strictly due to RLS
    -- Instead we'll validate in application code
    CONSTRAINT fk_created_by_user
        FOREIGN KEY (created_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL
);

COMMENT ON TABLE tenant_privileged_domains IS
    'Privileged email domains controlled by each tenant. Only super admins can manage. RLS enforces tenant isolation.';

COMMENT ON COLUMN tenant_privileged_domains.domain IS
    'Domain name without @ prefix (e.g., "company.com", "company.info")';

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_tenant_privileged_domains_tenant
    ON tenant_privileged_domains (tenant_id);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_privileged_domains TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE tenant_privileged_domains ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'tenant_privileged_domains'
                         AND policyname = 'tenant_privileged_domains_isolation') THEN
            CREATE POLICY tenant_privileged_domains_isolation ON tenant_privileged_domains
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

COMMIT;
