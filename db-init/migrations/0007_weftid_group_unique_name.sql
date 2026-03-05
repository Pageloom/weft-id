-- Enforce unique group names for WeftId-managed groups within a tenant.
-- IdP groups are exempt (they may have names that overlap with WeftId groups
-- or with groups from other IdPs).
-- migration-safety: ignore
SET LOCAL ROLE appowner;

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_weftid_name_unique
    ON public.groups (tenant_id, name)
    WHERE (idp_id IS NULL);

CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_idp_name_unique
    ON public.groups (tenant_id, idp_id, name)
    WHERE (idp_id IS NOT NULL);
