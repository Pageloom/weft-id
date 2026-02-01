-- ============================================================================
-- Group System - Phase 1: Core Infrastructure
--
-- This migration creates the foundation for organizing users into groups with
-- support for hierarchical relationships (DAG model with multi-parent).
--
-- Tables:
--   1) groups - Core group definitions (WeftID or IdP-sourced)
--   2) group_memberships - Direct user-to-group membership links
--   3) group_relationships - Direct parent-child edges between groups
--   4) group_lineage - Closure table for efficient ancestry queries
--
-- The closure table (group_lineage) pre-computes all ancestor-descendant
-- relationships for O(1) cycle detection and ancestry lookups.
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- TABLES
-- ============================================================================

-- Core group definitions
CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL CHECK (length(name) <= 200),
    description TEXT        NULL CHECK (description IS NULL OR length(description) <= 2000),
    group_type  TEXT        NOT NULL DEFAULT 'weftid' CHECK (group_type IN ('weftid', 'idp')),
    idp_id      UUID        NULL,  -- For Phase 2: links IdP groups to their source
    is_valid    BOOLEAN     NOT NULL DEFAULT true,
    created_by  UUID        NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Group names must be unique within a tenant
    UNIQUE (tenant_id, name)
);

COMMENT ON TABLE groups IS 'Group definitions scoped by tenant via RLS.';
COMMENT ON COLUMN groups.group_type IS 'weftid = manually created, idp = discovered from identity provider';
COMMENT ON COLUMN groups.idp_id IS 'For IdP groups, references the source identity provider';
COMMENT ON COLUMN groups.is_valid IS 'False when source IdP is deleted; group preserved for history';

-- Add composite unique constraint for FK references
ALTER TABLE groups ADD CONSTRAINT groups_id_tenant_unique UNIQUE (id, tenant_id);

-- User-to-group membership links
CREATE TABLE IF NOT EXISTS group_memberships (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL,
    group_id   UUID        NOT NULL,
    user_id    UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Each user can only be a member of a group once
    UNIQUE (group_id, user_id),

    -- Composite FK to groups (ensures tenant consistency)
    CONSTRAINT fk_group_memberships_group
        FOREIGN KEY (group_id, tenant_id)
            REFERENCES groups(id, tenant_id)
            ON DELETE CASCADE,

    -- Composite FK to users (ensures tenant consistency)
    CONSTRAINT fk_group_memberships_user
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES users(id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE group_memberships IS 'Direct user-to-group membership links.';

-- Direct parent-child edges between groups (for relationship management)
CREATE TABLE IF NOT EXISTS group_relationships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    parent_group_id UUID        NOT NULL,
    child_group_id  UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Each parent-child pair can only exist once
    UNIQUE (parent_group_id, child_group_id),

    -- Prevent self-relationships
    CONSTRAINT chk_no_self_relationship CHECK (parent_group_id != child_group_id),

    -- Composite FK to parent group
    CONSTRAINT fk_group_relationships_parent
        FOREIGN KEY (parent_group_id, tenant_id)
            REFERENCES groups(id, tenant_id)
            ON DELETE CASCADE,

    -- Composite FK to child group
    CONSTRAINT fk_group_relationships_child
        FOREIGN KEY (child_group_id, tenant_id)
            REFERENCES groups(id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE group_relationships IS 'Direct parent-child edges in the group hierarchy.';

-- Closure table for efficient ancestry queries
-- This table pre-computes all ancestor-descendant relationships for O(1) lookups.
-- Invariants:
--   - Every group has a self-referential row (ancestor=descendant, depth=0)
--   - Direct relationships have depth=1
--   - Transitive relationships have depth = sum of path depths
CREATE TABLE IF NOT EXISTS group_lineage (
    tenant_id     UUID    NOT NULL,
    ancestor_id   UUID    NOT NULL,
    descendant_id UUID    NOT NULL,
    depth         INTEGER NOT NULL CHECK (depth >= 0),

    -- Primary key on the relationship pair
    PRIMARY KEY (ancestor_id, descendant_id),

    -- Composite FK to ancestor group
    CONSTRAINT fk_group_lineage_ancestor
        FOREIGN KEY (ancestor_id, tenant_id)
            REFERENCES groups(id, tenant_id)
            ON DELETE CASCADE,

    -- Composite FK to descendant group
    CONSTRAINT fk_group_lineage_descendant
        FOREIGN KEY (descendant_id, tenant_id)
            REFERENCES groups(id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE group_lineage IS 'Closure table for O(1) ancestry queries. Self-rows have depth=0.';
COMMENT ON COLUMN group_lineage.depth IS '0=self, 1=direct parent/child, 2+=transitive';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Groups: lookup by tenant
CREATE INDEX IF NOT EXISTS idx_groups_tenant
    ON groups(tenant_id);

-- Groups: lookup by type (for filtering WeftID vs IdP groups)
CREATE INDEX IF NOT EXISTS idx_groups_tenant_type
    ON groups(tenant_id, group_type);

-- Group memberships: lookup by group (list members)
CREATE INDEX IF NOT EXISTS idx_group_memberships_group
    ON group_memberships(group_id);

-- Group memberships: lookup by user (list user's groups)
CREATE INDEX IF NOT EXISTS idx_group_memberships_user
    ON group_memberships(user_id);

-- Group relationships: lookup children of a group
CREATE INDEX IF NOT EXISTS idx_group_relationships_parent
    ON group_relationships(parent_group_id);

-- Group relationships: lookup parents of a group
CREATE INDEX IF NOT EXISTS idx_group_relationships_child
    ON group_relationships(child_group_id);

-- Group lineage: lookup all ancestors of a group (for access control)
CREATE INDEX IF NOT EXISTS idx_group_lineage_descendant
    ON group_lineage(descendant_id);

-- Group lineage: lookup all descendants of a group (for membership queries)
CREATE INDEX IF NOT EXISTS idx_group_lineage_ancestor
    ON group_lineage(ancestor_id);

-- Group lineage: filter by tenant for scoped queries
CREATE INDEX IF NOT EXISTS idx_group_lineage_tenant
    ON group_lineage(tenant_id);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE groups TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE group_memberships TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE group_relationships TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE group_lineage TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on groups table
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'groups'
          AND policyname = 'groups_tenant_isolation'
    ) THEN
        CREATE POLICY groups_tenant_isolation ON groups
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
    END IF;
END $$;

-- Enable RLS on group_memberships table
ALTER TABLE group_memberships ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'group_memberships'
          AND policyname = 'group_memberships_tenant_isolation'
    ) THEN
        CREATE POLICY group_memberships_tenant_isolation ON group_memberships
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
    END IF;
END $$;

-- Enable RLS on group_relationships table
ALTER TABLE group_relationships ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'group_relationships'
          AND policyname = 'group_relationships_tenant_isolation'
    ) THEN
        CREATE POLICY group_relationships_tenant_isolation ON group_relationships
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
    END IF;
END $$;

-- Enable RLS on group_lineage table
ALTER TABLE group_lineage ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'group_lineage'
          AND policyname = 'group_lineage_tenant_isolation'
    ) THEN
        CREATE POLICY group_lineage_tenant_isolation ON group_lineage
            USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
    END IF;
END $$;
