-- migration-safety: ignore (generalizes sp_group_assignments grant table to
-- also reference oauth2_clients as a third grant target: adds a nullable FK,
-- extends the one-of CHECK from two columns to three, and adds per-kind unique
-- + tenant indexes. Mirrors the proxy_apps addition in 0046.)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- oauth2_clients.available_to_all
--
-- An OIDC-enabled client can be flagged available to every user in the tenant
-- (no group grant needed), mirroring service_providers.available_to_all (0008)
-- and proxy_apps.available_to_all (0046). Default false: existing clients keep
-- today's behavior (plain OAuth2 clients never consult this flag).
-- ---------------------------------------------------------------------------

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS available_to_all boolean NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------------
-- Generalize sp_group_assignments: third nullable FK, one-of-three CHECK
--
-- The grant table already serves SAML service providers (sp_id) and proxy apps
-- (proxy_app_id) via two nullable FK columns, discriminated by which column is
-- populated (no app_kind column). This adds a third target: an OIDC-enabled
-- OAuth2 client. Existing rows are untouched and still CASCADE-delete with their
-- parent.
--
-- Steps, ordered so the live table is never in an invalid state:
--   1. Add nullable oauth2_client_id (FK + CASCADE).
--   2. Replace the two-column one-of CHECK with an exactly-one-of-three CHECK.
--      All existing rows satisfy it (exactly one of sp_id / proxy_app_id set).
--   3. Add a partial unique index + tenant index for the new kind, mirroring the
--      proxy_app_id indexes from 0046.
-- ---------------------------------------------------------------------------

ALTER TABLE sp_group_assignments
    ADD COLUMN oauth2_client_id UUID REFERENCES oauth2_clients(id) ON DELETE CASCADE;

ALTER TABLE sp_group_assignments
    DROP CONSTRAINT chk_sp_group_assignments_one_parent;

ALTER TABLE sp_group_assignments
    ADD CONSTRAINT chk_sp_group_assignments_one_parent
        CHECK (
            (
                (sp_id IS NOT NULL)::int
                + (proxy_app_id IS NOT NULL)::int
                + (oauth2_client_id IS NOT NULL)::int
            ) = 1
        );

CREATE UNIQUE INDEX uq_oauth2_client_group_assignment
    ON sp_group_assignments (oauth2_client_id, group_id)
    WHERE oauth2_client_id IS NOT NULL;

CREATE INDEX idx_sp_group_assignments_tenant_oauth2_client
    ON sp_group_assignments (tenant_id, oauth2_client_id)
    WHERE oauth2_client_id IS NOT NULL;
