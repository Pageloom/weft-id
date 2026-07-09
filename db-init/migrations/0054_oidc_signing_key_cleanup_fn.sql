-- Cross-tenant accessor for the retired-OIDC-signing-key cleanup sweep.
--
-- The worker's periodic sweep needs to find every tenant whose signing-key
-- rotation grace period has ended. The `oidc_signing_keys` RLS policy is
-- deliberately strict (an unscoped read fails closed so private key material
-- can never leak through an unset request scope), which also means a plain
-- UNSCOPED select from the worker sees nothing. Following the precedent set
-- by migration 0040 (`list_scim_enabled_sps_all_tenants_unscoped`), the sweep
-- routes through a SECURITY DEFINER function owned by appowner (table owners
-- are exempt from RLS) that exposes only the non-sensitive columns the sweep
-- needs -- never key material. The strict policy on the table is unchanged.

SET LOCAL ROLE appowner;

CREATE OR REPLACE FUNCTION list_oidc_signing_keys_needing_cleanup_unscoped()
RETURNS TABLE (
    id uuid,
    tenant_id uuid,
    previous_kid character varying(64),
    rotation_grace_period_ends_at timestamp with time zone
)
LANGUAGE sql
SECURITY DEFINER
-- Pin search_path so an attacker cannot redirect the table reference
-- by setting a shadowing schema. Fully-qualified table name below.
SET search_path = public, pg_catalog
AS $$
    SELECT id, tenant_id, previous_kid, rotation_grace_period_ends_at
    FROM public.oidc_signing_keys
    WHERE rotation_grace_period_ends_at IS NOT NULL
      AND rotation_grace_period_ends_at < now()
$$;

REVOKE ALL ON FUNCTION list_oidc_signing_keys_needing_cleanup_unscoped() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_oidc_signing_keys_needing_cleanup_unscoped() TO appuser;

RESET ROLE;
