-- ============================================================================
-- SP Group Assignments
--
-- This migration adds group-based access control for downstream Service
-- Providers. Access to SPs is controlled via group-to-SP assignments,
-- leveraging the existing group hierarchy (DAG with closure table).
--
-- Also adds an optional description column to service_providers.
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- ALTER: Add description to service_providers
-- ============================================================================

ALTER TABLE service_providers ADD COLUMN IF NOT EXISTS description TEXT;

COMMENT ON COLUMN service_providers.description IS
    'Optional human-readable description of the service provider.';


-- ============================================================================
-- TABLE: sp_group_assignments
-- Maps service providers to groups for access control
-- ============================================================================

CREATE TABLE IF NOT EXISTS sp_group_assignments
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sp_id       UUID        NOT NULL REFERENCES service_providers(id) ON DELETE CASCADE,
    group_id    UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_by UUID        NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_sp_group_assignment UNIQUE (sp_id, group_id)
);

COMMENT ON TABLE sp_group_assignments IS
    'Maps service providers to groups for access control. A user can access an SP if they belong to any assigned group (or a descendant of an assigned group).';

COMMENT ON COLUMN sp_group_assignments.assigned_by IS
    'User ID of the admin who created this assignment.';


-- ============================================================================
-- INDEXES
-- ============================================================================

-- Look up assignments by SP within a tenant
CREATE INDEX IF NOT EXISTS idx_sp_group_assignments_tenant_sp
    ON sp_group_assignments (tenant_id, sp_id);

-- Look up assignments by group within a tenant
CREATE INDEX IF NOT EXISTS idx_sp_group_assignments_tenant_group
    ON sp_group_assignments (tenant_id, group_id);


-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE sp_group_assignments TO appuser;


-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE sp_group_assignments ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'sp_group_assignments'
                         AND policyname = 'sp_group_assignments_tenant_isolation') THEN
            CREATE POLICY sp_group_assignments_tenant_isolation ON sp_group_assignments
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;
