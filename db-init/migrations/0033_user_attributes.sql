-- migration-safety: ignore (new tables; new column on users has DEFAULT)
-- Standard user attribute storage: data model + tenant attribute config.
--
-- This migration creates the full two-space user-attribute storage in one shot:
--
--   user_attributes
--     Canonical user attribute set, owned by user/admin. Read by SP assertion
--     builders. One row per (user, attribute_key). The row exists because
--     someone (user, admin, or the IdP-mirror writer) put it there.
--
--   user_idp_attributes
--     Read-only audit/info copy of what each connected IdP last sent. One row
--     per (user, idp_id, attribute_key). Visible to admins for diagnostics;
--     never overwritten by user/admin edits. CASCADE on user and IdP delete.
--
--   tenant_attribute_config
--     Per-tenant per-attribute toggles (enabled, required, send_to_sps_default,
--     mirror_from_idp, locked_for_users).
--
--   users.force_profile_completion
--     Admin-set flag that gates the user behind a completion screen until they
--     fill every required+enabled+unlocked attribute. Safe on PG12+: adding a
--     NOT NULL BOOLEAN with DEFAULT FALSE does not rewrite the existing rows.
--
-- The registry in app/constants/user_attributes.py is the runtime source of
-- truth. The seed VALUES list below MUST stay in sync with it. Adding a 15th
-- attribute requires a follow-up migration that inserts the new key for every
-- existing tenant.

SET LOCAL ROLE appowner;

-- ============================================================================
-- 1. user_attributes (canonical EAV table)
-- ============================================================================
CREATE TABLE user_attributes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    attribute_key VARCHAR(64) NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_attributes_user_attr_unique UNIQUE (user_id, attribute_key),
    CONSTRAINT user_attributes_user_tenant_fkey
        FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT user_attributes_value_length_check CHECK (length(value) <= 2000)
);

CREATE INDEX user_attributes_tenant_user_idx
    ON user_attributes (tenant_id, user_id);
CREATE INDEX user_attributes_tenant_key_idx
    ON user_attributes (tenant_id, attribute_key);

ALTER TABLE user_attributes ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_attributes_tenant_isolation
    ON user_attributes
    FOR ALL
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_attributes TO appuser;

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
-- 3. tenant_attribute_config (per-tenant per-attribute toggles)
-- ============================================================================
CREATE TABLE tenant_attribute_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    attribute_key VARCHAR(64) NOT NULL,
    category VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    required BOOLEAN NOT NULL DEFAULT FALSE,
    send_to_sps_default BOOLEAN NOT NULL DEFAULT TRUE,
    mirror_from_idp BOOLEAN NOT NULL DEFAULT FALSE,
    locked_for_users BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT tenant_attribute_config_unique UNIQUE (tenant_id, attribute_key),
    CONSTRAINT tenant_attribute_config_category_check
        CHECK (category IN ('contact', 'professional', 'location', 'profile'))
);

CREATE INDEX tenant_attribute_config_tenant_idx
    ON tenant_attribute_config (tenant_id);

ALTER TABLE tenant_attribute_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_attribute_config_tenant_isolation
    ON tenant_attribute_config
    FOR ALL
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_attribute_config TO appuser;

-- ============================================================================
-- 4. users.force_profile_completion
-- ----------------------------------------------------------------------------
-- ADD COLUMN ... NOT NULL DEFAULT false is safe on PG12+: the default is stored
-- as a table-level constant rather than rewriting every existing row, so this
-- DDL is effectively instantaneous regardless of users table size.
-- ============================================================================
ALTER TABLE users
    ADD COLUMN force_profile_completion BOOLEAN NOT NULL DEFAULT FALSE;

-- ============================================================================
-- 5. Seed tenant_attribute_config for every existing tenant
-- ----------------------------------------------------------------------------
-- The (key, category) pairs below MUST match
-- app/constants/user_attributes.py STANDARD_ATTRIBUTES. Adding a 15th attribute
-- requires a follow-up migration that inserts the new row for each tenant.
-- All attributes default to enabled=false, required=false,
-- send_to_sps_default=true, mirror_from_idp=false, locked_for_users=false.
-- Surface stays invisible until tenants opt in. The default for
-- mirror_from_idp is flipped to TRUE in a later migration; this seed predates
-- that flip and pre-existing tenants are migrated by the UPDATE there.
-- ============================================================================
INSERT INTO tenant_attribute_config (
    tenant_id, attribute_key, category, enabled, required, send_to_sps_default
)
SELECT
    t.id,
    a.attribute_key,
    a.category,
    FALSE,
    FALSE,
    TRUE
FROM tenants t
CROSS JOIN (
    VALUES
        ('phone_work',         'contact'),
        ('phone_mobile',       'contact'),
        ('display_name',       'professional'),
        ('job_title',          'professional'),
        ('department',         'professional'),
        ('organization',       'professional'),
        ('employee_id',        'professional'),
        ('street_address',     'location'),
        ('city',               'location'),
        ('state',              'location'),
        ('postal_code',        'location'),
        ('country',            'location'),
        ('preferred_language', 'profile'),
        ('description',        'profile')
) AS a(attribute_key, category)
ON CONFLICT (tenant_id, attribute_key) DO NOTHING;
