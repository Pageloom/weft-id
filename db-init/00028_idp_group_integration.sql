-- ============================================================================
-- Group System - Phase 2: IdP Group Integration
--
-- This migration adds:
--   1) FK constraint linking groups.idp_id to saml_identity_providers
--   2) Index for efficient IdP group lookups
--
-- When an IdP is deleted, ON DELETE SET NULL preserves the group with
-- idp_id=NULL and is_valid=false for historical reference.
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- FOREIGN KEY CONSTRAINT
-- ============================================================================

-- Add FK constraint on groups.idp_id referencing saml_identity_providers
-- ON DELETE SET NULL allows groups to persist when their source IdP is deleted
-- (the service layer sets is_valid=false before deletion)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_groups_idp'
          AND table_name = 'groups'
    ) THEN
        ALTER TABLE groups
        ADD CONSTRAINT fk_groups_idp
        FOREIGN KEY (idp_id) REFERENCES saml_identity_providers(id) ON DELETE SET NULL;
    END IF;
END $$;

-- ============================================================================
-- UNIQUE CONSTRAINT MIGRATION
-- ============================================================================

-- The original constraint was: UNIQUE (tenant_id, name)
-- This enforced uniqueness across ALL groups within a tenant.
--
-- New requirement: IdP groups should be namespaced to their IdP, meaning:
--   - WeftID groups must have unique names within the tenant
--   - IdP groups must have unique names within their IdP (different IdPs can
--     have groups with the same name)
--   - IdP groups can share names with WeftID groups (they're conceptually
--     different namespaces)
--
-- We implement this with two partial unique indexes:
--   1. For WeftID groups: unique (tenant_id, name) where idp_id IS NULL
--   2. For IdP groups: unique (tenant_id, idp_id, name) where idp_id IS NOT NULL

-- Drop the old constraint that enforced global uniqueness
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'groups_tenant_id_name_key'
          AND table_name = 'groups'
    ) THEN
        ALTER TABLE groups DROP CONSTRAINT groups_tenant_id_name_key;
    END IF;
END $$;

-- Create partial unique index for WeftID groups (idp_id IS NULL)
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_weftid_name_unique
    ON groups(tenant_id, name) WHERE idp_id IS NULL;

-- Create partial unique index for IdP groups (idp_id IS NOT NULL)
-- This ensures group names are unique within each IdP
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_idp_name_unique
    ON groups(tenant_id, idp_id, name) WHERE idp_id IS NOT NULL;

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Index for efficient IdP group lookups (partial index excludes NULL idp_id)
CREATE INDEX IF NOT EXISTS idx_groups_idp_id
    ON groups(idp_id) WHERE idp_id IS NOT NULL;

COMMIT;
