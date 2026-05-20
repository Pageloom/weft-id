-- Revert the relaxed service_providers RLS policy from 0037 back to strict,
-- and route the SCIM cleanup job's cross-tenant scan through a
-- SECURITY DEFINER function instead.
--
-- Background: migration 0037 widened the policy on `service_providers` so
-- the cleanup job (running with no `app.tenant_id` set) could see every
-- SCIM-enabled SP across tenants. That widening makes the entire table
-- visible whenever the setting is unset, which is a much larger blast
-- radius than the cleanup job actually needs. SCIM-specific tables
-- (`scim_push_queue`, `scim_sync_log`, `sp_scim_credentials`) keep the
-- widened policy because they hold only SCIM data and the worker
-- genuinely needs cross-tenant access; `service_providers` does not.
--
-- The new SECURITY DEFINER function `list_scim_enabled_sps_all_tenants_unscoped()`
-- runs with definer privileges (which can bypass RLS as table owner) and
-- returns exactly the three columns the cleanup job needs. The function
-- pins `search_path` to public and uses fully-qualified table names to
-- avoid trojan-search-path attacks (standard SECURITY DEFINER hardening).

-- Revert service_providers to the strict policy. NULLIF-only (no CASE).
-- Matches the baseline schema definition.
DROP POLICY IF EXISTS service_providers_tenant_isolation ON service_providers;
CREATE POLICY service_providers_tenant_isolation ON service_providers
    USING (
        tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid
    )
    WITH CHECK (
        tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid
    );

-- SECURITY DEFINER function: returns the three columns the nightly
-- SCIM-log cleanup job needs (id, tenant_id, scim_log_retention) for
-- every SCIM-enabled SP across every tenant. Owned by appowner because
-- the underlying table is owned by appowner; a SECURITY DEFINER
-- function inherits the definer's RLS-bypass privilege (or rather:
-- table owners are exempt from RLS unless FORCE ROW LEVEL SECURITY is
-- set on the table).
SET LOCAL ROLE appowner;

CREATE OR REPLACE FUNCTION list_scim_enabled_sps_all_tenants_unscoped()
RETURNS TABLE (
    id uuid,
    tenant_id uuid,
    scim_log_retention text
)
LANGUAGE sql
SECURITY DEFINER
-- Pin search_path so an attacker cannot redirect the table reference
-- by setting a shadowing schema. Fully-qualified table name below.
SET search_path = public, pg_catalog
AS $$
    SELECT id, tenant_id, scim_log_retention
    FROM public.service_providers
    WHERE scim_enabled = true
$$;

REVOKE ALL ON FUNCTION list_scim_enabled_sps_all_tenants_unscoped() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_scim_enabled_sps_all_tenants_unscoped() TO appuser;

RESET ROLE;
