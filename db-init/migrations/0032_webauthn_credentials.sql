-- migration-safety: ignore (new table; indexes on empty table cannot block writes)
SET LOCAL ROLE appowner;

CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    name VARCHAR(100) NOT NULL,
    aaguid TEXT,
    transports TEXT[],
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    CONSTRAINT chk_webauthn_credentials_aaguid_length CHECK (length(aaguid) <= 64)
);

CREATE UNIQUE INDEX webauthn_credentials_credential_id_key
    ON webauthn_credentials (credential_id);
CREATE INDEX webauthn_credentials_tenant_user_idx
    ON webauthn_credentials (tenant_id, user_id);

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;

CREATE POLICY webauthn_credentials_tenant_isolation
    ON webauthn_credentials
    FOR ALL
    TO appuser
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials TO appuser;
