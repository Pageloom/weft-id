-- migration-safety: ignore (Iteration 1 columns dropped pre-merge; new table; new columns have DEFAULT)
-- Two-space storage pivot for user attributes.
--
-- Supersedes the source / source_idp_id columns shipped in 0033 with a
-- separate user_idp_attributes table. After this migration:
--
--   user_attributes:
--     Canonical user attribute set, owned by user/admin. Read by SP
--     assertion builders. One row per (user, attribute_key). No source
--     enum -- the row exists because someone (user, admin, or the IdP-
--     mirror writer) put it there.
--
--   user_idp_attributes:
--     Read-only audit/info copy of what each connected IdP last sent. One
--     row per (user, idp_id, attribute_key). Visible to admins for
--     diagnostics; never overwritten by user/admin edits. CASCADE on user
--     and IdP delete.
--
--   tenant_attribute_config:
--     Two new flags -- mirror_from_idp (default false: info-only) and
--     locked_for_users (default false: users can edit).
--
-- Iteration 1 didn't write any production rows to user_attributes
-- (the feature branch is unmerged), so dropping the source columns is
-- safe without a data migration step.

SET LOCAL ROLE appowner;

-- ============================================================================
-- 1. Drop source/source_idp_id from user_attributes
-- ============================================================================
ALTER TABLE user_attributes
    DROP CONSTRAINT IF EXISTS user_attributes_source_idp_consistency_check;
ALTER TABLE user_attributes
    DROP CONSTRAINT IF EXISTS user_attributes_source_check;
ALTER TABLE user_attributes
    DROP CONSTRAINT IF EXISTS user_attributes_idp_fkey;
ALTER TABLE user_attributes DROP COLUMN IF EXISTS source_idp_id;
ALTER TABLE user_attributes DROP COLUMN IF EXISTS source;

-- ============================================================================
-- 2. user_idp_attributes (per-IdP read-only audit snapshot)
-- ============================================================================
CREATE TABLE user_idp_attributes (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    idp_id UUID NOT NULL,
    attribute_key VARCHAR(64) NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, idp_id, attribute_key),
    CONSTRAINT user_idp_attributes_user_tenant_fkey
        FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT user_idp_attributes_idp_fkey
        FOREIGN KEY (idp_id)
        REFERENCES saml_identity_providers(id) ON DELETE CASCADE,
    CONSTRAINT user_idp_attributes_value_length_check CHECK (length(value) <= 2000)
);

CREATE INDEX user_idp_attributes_tenant_user_idx
    ON user_idp_attributes (tenant_id, user_id);
CREATE INDEX user_idp_attributes_tenant_idp_idx
    ON user_idp_attributes (tenant_id, idp_id);

ALTER TABLE user_idp_attributes ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_idp_attributes_tenant_isolation
    ON user_idp_attributes
    FOR ALL
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_idp_attributes TO appuser;

-- ============================================================================
-- 3. tenant_attribute_config new flags
-- ============================================================================
ALTER TABLE tenant_attribute_config
    ADD COLUMN mirror_from_idp BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_attribute_config
    ADD COLUMN locked_for_users BOOLEAN NOT NULL DEFAULT FALSE;
