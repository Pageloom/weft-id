-- migration-safety: ignore (new tables; indexes on empty tables cannot block writes)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- service_providers: SCIM target columns
-- ---------------------------------------------------------------------------

ALTER TABLE service_providers
    ADD COLUMN IF NOT EXISTS scim_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS scim_target_url VARCHAR(2048),
    ADD COLUMN IF NOT EXISTS scim_kind VARCHAR(50) NOT NULL DEFAULT 'generic',
    ADD COLUMN IF NOT EXISTS scim_membership_mode VARCHAR(20) NOT NULL DEFAULT 'effective',
    ADD COLUMN IF NOT EXISTS scim_log_retention VARCHAR(10) NOT NULL DEFAULT '3';

ALTER TABLE service_providers
    ADD CONSTRAINT chk_service_providers_scim_membership_mode
        CHECK (scim_membership_mode IN ('effective', 'direct'));

ALTER TABLE service_providers
    ADD CONSTRAINT chk_service_providers_scim_log_retention
        CHECK (scim_log_retention IN ('3', '6', '12', '24', 'forever'));

-- Note: no CHECK constraint on scim_kind. Validation lives in code (Pydantic
-- enum in API, dropdown in UI); unknown values fall back to the 'generic'
-- quirk module at runtime so adding a new quirk module doesn't need a migration.

-- ---------------------------------------------------------------------------
-- sp_scim_credentials: bearer tokens issued to WeftID by the downstream SP
-- ---------------------------------------------------------------------------

CREATE TABLE sp_scim_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sp_id UUID NOT NULL REFERENCES service_providers(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX sp_scim_credentials_token_hash_key
    ON sp_scim_credentials (token_hash);
CREATE INDEX sp_scim_credentials_sp_active_idx
    ON sp_scim_credentials (sp_id)
    WHERE revoked_at IS NULL;
CREATE INDEX sp_scim_credentials_tenant_idx
    ON sp_scim_credentials (tenant_id);

ALTER TABLE sp_scim_credentials ENABLE ROW LEVEL SECURITY;

CREATE POLICY sp_scim_credentials_tenant_isolation
    ON sp_scim_credentials
    FOR ALL
    TO appuser
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON sp_scim_credentials TO appuser;

-- ---------------------------------------------------------------------------
-- scim_push_queue: coalescing outbox for outbound SCIM pushes
-- ---------------------------------------------------------------------------

CREATE TABLE scim_push_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sp_id UUID NOT NULL REFERENCES service_providers(id) ON DELETE CASCADE,
    resource_type VARCHAR(10) NOT NULL,
    resource_id UUID NOT NULL,
    enqueued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    last_error TEXT,
    dead_letter_at TIMESTAMPTZ,
    CONSTRAINT chk_scim_push_queue_resource_type
        CHECK (resource_type IN ('user', 'group')),
    CONSTRAINT chk_scim_push_queue_last_error_length
        CHECK (last_error IS NULL OR length(last_error) <= 4000),
    CONSTRAINT uq_scim_push_queue_target
        UNIQUE (sp_id, resource_type, resource_id)
);

CREATE INDEX scim_push_queue_tenant_idx
    ON scim_push_queue (tenant_id);
CREATE INDEX scim_push_queue_ready_idx
    ON scim_push_queue (sp_id, next_attempt_at)
    WHERE dead_letter_at IS NULL;

ALTER TABLE scim_push_queue ENABLE ROW LEVEL SECURITY;

CREATE POLICY scim_push_queue_tenant_isolation
    ON scim_push_queue
    FOR ALL
    TO appuser
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_push_queue TO appuser;

-- ---------------------------------------------------------------------------
-- scim_sync_log: per-push outcome history (separate from main audit log)
-- ---------------------------------------------------------------------------

CREATE TABLE scim_sync_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sp_id UUID NOT NULL REFERENCES service_providers(id) ON DELETE CASCADE,
    resource_type VARCHAR(10) NOT NULL,
    resource_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_scim_sync_log_resource_type
        CHECK (resource_type IN ('user', 'group')),
    CONSTRAINT chk_scim_sync_log_status
        CHECK (status IN ('pending', 'running', 'done', 'failed', 'dead_letter')),
    CONSTRAINT chk_scim_sync_log_error_length
        CHECK (error IS NULL OR length(error) <= 4000)
);

CREATE INDEX scim_sync_log_tenant_idx
    ON scim_sync_log (tenant_id);
CREATE INDEX scim_sync_log_sp_completed_idx
    ON scim_sync_log (sp_id, completed_at);
CREATE INDEX scim_sync_log_sp_status_idx
    ON scim_sync_log (sp_id, status);

ALTER TABLE scim_sync_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY scim_sync_log_tenant_isolation
    ON scim_sync_log
    FOR ALL
    TO appuser
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_sync_log TO appuser;
