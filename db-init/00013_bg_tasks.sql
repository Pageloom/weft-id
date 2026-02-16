-- Background Tasks Table
-- This is a system table for cross-tenant job processing.
-- NO RLS - the worker process polls this table without tenant context.
-- The worker sets SET LOCAL app.tenant_id before executing job handlers.

BEGIN;
SET LOCAL ROLE appowner;

CREATE TABLE IF NOT EXISTS bg_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_type        TEXT NOT NULL CHECK (length(job_type) <= 100),
    payload         JSONB NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    result          JSONB NULL,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ NULL,
    completed_at    TIMESTAMPTZ NULL,
    error           TEXT NULL
);

-- Index for worker polling: find pending tasks efficiently
CREATE INDEX idx_bg_tasks_pending ON bg_tasks(created_at)
    WHERE status = 'pending';

-- Index for admin queries: list tasks by tenant
CREATE INDEX idx_bg_tasks_tenant_created ON bg_tasks(tenant_id, created_at DESC);

-- Index for lookups by job type within tenant
CREATE INDEX idx_bg_tasks_tenant_type ON bg_tasks(tenant_id, job_type, created_at DESC);

-- Grant permissions to appuser (worker runs as appuser)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE bg_tasks TO appuser;

COMMIT;
