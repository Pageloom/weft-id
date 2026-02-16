-- Export Files Table
-- Tracks export files for download and cleanup.
-- RLS enabled for tenant isolation.

BEGIN;
SET LOCAL ROLE appowner;

CREATE TABLE IF NOT EXISTS export_files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bg_task_id      UUID NULL REFERENCES bg_tasks(id) ON DELETE SET NULL,
    filename        TEXT NOT NULL,
    storage_type    TEXT NOT NULL CHECK (storage_type IN ('local', 'spaces')),
    storage_path    TEXT NOT NULL,
    file_size       BIGINT NULL,
    content_type    TEXT NOT NULL DEFAULT 'application/gzip',
    expires_at      TIMESTAMPTZ NOT NULL,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    downloaded_at   TIMESTAMPTZ NULL
);

-- Index for tenant queries
CREATE INDEX idx_export_files_tenant_created ON export_files(tenant_id, created_at DESC);

-- Index for cleanup job: find expired files efficiently
CREATE INDEX idx_export_files_expired ON export_files(expires_at)
    WHERE expires_at IS NOT NULL;

-- Enable Row Level Security
ALTER TABLE export_files ENABLE ROW LEVEL SECURITY;

-- RLS policy: tenant isolation
-- Allow full access when app.tenant_id is not set (for worker/cleanup processes)
-- Otherwise, restrict to matching tenant
-- Uses CASE to prevent UUID cast errors when tenant_id is empty
CREATE POLICY export_files_tenant_isolation ON export_files
    USING (
        CASE
            WHEN NULLIF(current_setting('app.tenant_id', true), '') IS NULL THEN true
            ELSE tenant_id = current_setting('app.tenant_id', true)::uuid
        END
    )
    WITH CHECK (
        CASE
            WHEN NULLIF(current_setting('app.tenant_id', true), '') IS NULL THEN true
            ELSE tenant_id = current_setting('app.tenant_id', true)::uuid
        END
    );

-- Grant permissions to appuser
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE export_files TO appuser;

COMMIT;
