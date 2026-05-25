-- migration-safety: ignore (new table; indexes on empty table cannot block writes)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- scim_inbound_tokens: bearer tokens accepted by WeftID's inbound SCIM
-- endpoint family. Issued one per upstream IdP connection. Stored as a
-- SHA-256 hash so plaintext recovery is impossible.
-- ---------------------------------------------------------------------------

CREATE TABLE scim_inbound_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_id UUID NOT NULL REFERENCES saml_identity_providers(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,
    name VARCHAR(255),
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT chk_scim_inbound_tokens_token_hash_hex
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_scim_inbound_tokens_name_length
        CHECK (name IS NULL OR length(name) <= 255)
);

-- Token hash is globally unique: hash collisions across tenants would be a
-- cross-tenant authentication bypass, so we enforce uniqueness platform-wide
-- (the index runs without RLS because it's a unique constraint on the table
-- definition, not a tenant-scoped query). SHA-256 makes collisions
-- astronomically improbable; the constraint is defence-in-depth.
CREATE UNIQUE INDEX scim_inbound_tokens_token_hash_key
    ON scim_inbound_tokens (token_hash);

CREATE INDEX scim_inbound_tokens_idp_active_idx
    ON scim_inbound_tokens (idp_id)
    WHERE revoked_at IS NULL;

CREATE INDEX scim_inbound_tokens_tenant_idx
    ON scim_inbound_tokens (tenant_id);

ALTER TABLE scim_inbound_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY scim_inbound_tokens_tenant_isolation
    ON scim_inbound_tokens
    FOR ALL
    TO appuser
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_inbound_tokens TO appuser;
