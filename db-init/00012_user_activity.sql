-- ============================================================================
-- User Activity Tracking
--
-- This migration creates the user_activity table for tracking when users
-- last interacted with the system. Separate from users table for cleaner
-- schema and future extensibility.
--
-- Design principles:
--   - One-to-one relationship with users (CASCADE on delete)
--   - Tenant-scoped via RLS
--   - UPSERT pattern for efficient updates
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- TABLE: user_activity
-- ============================================================================

CREATE TABLE IF NOT EXISTS user_activity
(
    user_id          UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    tenant_id        UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE user_activity IS
    'Tracks when users last interacted with the system. One record per user.';

COMMENT ON COLUMN user_activity.last_activity_at IS
    'Timestamp of user last activity. Updated on writes and periodically on reads (3-hour cache).';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Query by tenant + activity time (for admin dashboards, idle user reports)
CREATE INDEX IF NOT EXISTS idx_user_activity_tenant_time
    ON user_activity (tenant_id, last_activity_at DESC);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE ON TABLE user_activity TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE user_activity ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'user_activity'
                         AND policyname = 'user_activity_tenant_isolation') THEN
            CREATE POLICY user_activity_tenant_isolation ON user_activity
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;
