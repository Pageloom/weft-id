-- Attribute provenance + trusted-source SP emission.
--
-- Closes a broken-access-control gap: a self-editable standard attribute
-- (e.g. department, employee_id) was emitted into signed SAML assertions with
-- no indication of who set it, so a downstream SP could trust a user-asserted
-- value as IdP/admin-grade truth.
--
-- Two changes:
--
--   user_attributes.source
--     Per-row provenance: 'idp' (mirrored from an upstream IdP login), 'admin'
--     (set by an admin), or 'self' (set by the user themselves). Written at
--     each canonical write site. Read by the assertion builder to decide what
--     may cross into a signed assertion.
--
--   tenant_attribute_config.allow_self_sourced_to_sp
--     Per-attribute opt-in. When FALSE (the secure default), self-sourced
--     values are withheld from SP assertions. An admin sets it TRUE only for
--     attributes where user-asserted values are safe to propagate.
--
-- Backfill: existing canonical rows have no recorded source. A row is
-- classified 'idp' when its value matches the user's current IdP-mirror
-- snapshot (user_idp_attributes) for the same key; every other existing row
-- defaults to 'admin'. No existing row is marked 'self', so nothing currently
-- flowing to SPs stops on upgrade -- only future self-edits are gated.
--
-- Adding NOT NULL columns with a DEFAULT does not rewrite existing rows on
-- PG11+, so this is safe to apply on a running instance.

SET LOCAL ROLE appowner;

-- ============================================================================
-- 1. user_attributes.source
-- ============================================================================
ALTER TABLE user_attributes
    ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'admin'
    CONSTRAINT user_attributes_source_check
        CHECK (source IN ('idp', 'admin', 'self'));

-- Backfill provenance for pre-existing rows: 'idp' when the canonical value
-- still matches a current IdP-mirror snapshot, else leave the 'admin' default.
UPDATE user_attributes ua
SET source = 'idp'
WHERE EXISTS (
    SELECT 1
      FROM user_idp_attributes uia
     WHERE uia.user_id = ua.user_id
       AND uia.attribute_key = ua.attribute_key
       AND uia.value = ua.value
);

-- ============================================================================
-- 2. tenant_attribute_config.allow_self_sourced_to_sp
-- ============================================================================
ALTER TABLE tenant_attribute_config
    ADD COLUMN allow_self_sourced_to_sp BOOLEAN NOT NULL DEFAULT FALSE;
