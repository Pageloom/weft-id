-- ============================================================================
-- Service Layer Event Logging
--
-- This migration creates the event_logs table for auditing all service layer
-- write operations. Each log entry captures who did what, when, and to what.
--
-- Design principles:
--   - Synchronous logging (write completes before service returns)
--   - Immutable audit trail (no UPDATE/DELETE on logs)
--   - Tenant-scoped via RLS
--   - Flexible event_type as TEXT (not enum) for extensibility
--   - JSON metadata for context-specific details
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- TABLE: event_logs
-- ============================================================================

CREATE TABLE IF NOT EXISTS event_logs
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    actor_user_id   UUID        NOT NULL,  -- Who performed the action (user ID or SYSTEM_ACTOR_ID)
    artifact_type   TEXT        NOT NULL CHECK (length(artifact_type) <= 100),
    artifact_id     UUID        NOT NULL,  -- ID of the affected entity
    event_type      TEXT        NOT NULL CHECK (length(event_type) <= 100),
    metadata        JSONB       NULL,      -- Optional context-specific details
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE event_logs IS
    'Audit log for all service layer write operations. Scoped by tenant via RLS.';

COMMENT ON COLUMN event_logs.actor_user_id IS
    'User who performed the action. System-initiated actions use SYSTEM_ACTOR_ID constant.';

COMMENT ON COLUMN event_logs.artifact_type IS
    'Type of entity affected (e.g., user, privileged_domain, tenant_settings).';

COMMENT ON COLUMN event_logs.artifact_id IS
    'UUID of the affected entity.';

COMMENT ON COLUMN event_logs.event_type IS
    'Descriptive action string (e.g., user_created, email_verified, mfa_enabled).';

COMMENT ON COLUMN event_logs.metadata IS
    'Optional JSON object with context-specific details.';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Query by tenant + time range (common for admin UI/API)
CREATE INDEX IF NOT EXISTS idx_event_logs_tenant_created
    ON event_logs (tenant_id, created_at DESC);

-- Query by actor (who did what)
CREATE INDEX IF NOT EXISTS idx_event_logs_actor
    ON event_logs (tenant_id, actor_user_id, created_at DESC);

-- Query by artifact (what happened to this entity)
CREATE INDEX IF NOT EXISTS idx_event_logs_artifact
    ON event_logs (tenant_id, artifact_type, artifact_id, created_at DESC);

-- Query by event type
CREATE INDEX IF NOT EXISTS idx_event_logs_event_type
    ON event_logs (tenant_id, event_type, created_at DESC);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

-- Only allow INSERT and SELECT (no UPDATE/DELETE for audit integrity)
GRANT SELECT, INSERT ON TABLE event_logs TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE event_logs ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'event_logs'
                         AND policyname = 'event_logs_tenant_isolation') THEN
            CREATE POLICY event_logs_tenant_isolation ON event_logs
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

COMMIT;
