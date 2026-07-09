-- Fix four silently-broken worker sweeps: route their cross-tenant listing
-- queries through SECURITY DEFINER accessors.
--
-- Background: the UNSCOPED sentinel only skips `SET LOCAL app.tenant_id`; it
-- does not bypass RLS. Tables with the strict tenant-isolation policy fail
-- closed when the setting is unset, so the worker (connecting as appuser,
-- NOBYPASSRLS) saw zero rows from its plain UNSCOPED selects. Four periodic
-- jobs were therefore silent no-ops: SP signing certificate auto-rotation and
-- cleanup, per-IdP SP certificate auto-rotation and cleanup, SAML metadata
-- refresh, and idle-user auto-inactivation.
--
-- Following the precedent set by migration 0040
-- (`list_scim_enabled_sps_all_tenants_unscoped`) and reused by 0054, each
-- sweep gets a SECURITY DEFINER function owned by appowner (table owners are
-- exempt from RLS) that exposes only the columns the sweep needs. The strict
-- policies on the underlying tables are unchanged; the jobs re-scope to the
-- owning tenant for every subsequent read and write.
--
-- All functions pin search_path and use fully-qualified table names
-- (standard SECURITY DEFINER hardening against trojan-search-path attacks).

SET LOCAL ROLE appowner;

-- 1. SP signing certificates needing rotation (expires within the tenant's
--    configured window, no rotation in progress) or cleanup (grace expired).
CREATE OR REPLACE FUNCTION list_sp_signing_certificates_for_rotation_unscoped()
RETURNS TABLE (
    id uuid,
    sp_id uuid,
    tenant_id uuid,
    expires_at timestamp with time zone,
    rotation_grace_period_ends_at timestamp with time zone,
    action text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT sc.id, sc.sp_id, sc.tenant_id, sc.expires_at,
           sc.rotation_grace_period_ends_at,
           'rotate'::text AS action
    FROM public.sp_signing_certificates sc
    LEFT JOIN public.tenant_security_settings tss
        ON tss.tenant_id = sc.tenant_id
    WHERE sc.expires_at < now() + make_interval(
        days => coalesce(tss.certificate_rotation_window_days, 90)
    )
      AND sc.rotation_grace_period_ends_at IS NULL
    UNION ALL
    SELECT sc.id, sc.sp_id, sc.tenant_id, sc.expires_at,
           sc.rotation_grace_period_ends_at,
           'cleanup'::text AS action
    FROM public.sp_signing_certificates sc
    WHERE sc.rotation_grace_period_ends_at IS NOT NULL
      AND sc.rotation_grace_period_ends_at < now()
$$;

REVOKE ALL ON FUNCTION list_sp_signing_certificates_for_rotation_unscoped() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_sp_signing_certificates_for_rotation_unscoped() TO appuser;

-- 2. Per-IdP SP certificates needing rotation or cleanup (same shape).
CREATE OR REPLACE FUNCTION list_idp_sp_certificates_for_rotation_unscoped()
RETURNS TABLE (
    id uuid,
    idp_id uuid,
    tenant_id uuid,
    expires_at timestamp with time zone,
    rotation_grace_period_ends_at timestamp with time zone,
    action text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT sc.id, sc.idp_id, sc.tenant_id, sc.expires_at,
           sc.rotation_grace_period_ends_at,
           'rotate'::text AS action
    FROM public.saml_idp_sp_certificates sc
    LEFT JOIN public.tenant_security_settings tss
        ON tss.tenant_id = sc.tenant_id
    WHERE sc.expires_at < now() + make_interval(
        days => coalesce(tss.certificate_rotation_window_days, 90)
    )
      AND sc.rotation_grace_period_ends_at IS NULL
    UNION ALL
    SELECT sc.id, sc.idp_id, sc.tenant_id, sc.expires_at,
           sc.rotation_grace_period_ends_at,
           'cleanup'::text AS action
    FROM public.saml_idp_sp_certificates sc
    WHERE sc.rotation_grace_period_ends_at IS NOT NULL
      AND sc.rotation_grace_period_ends_at < now()
$$;

REVOKE ALL ON FUNCTION list_idp_sp_certificates_for_rotation_unscoped() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_idp_sp_certificates_for_rotation_unscoped() TO appuser;

-- 3. SAML IdPs with a metadata URL (for the daily metadata refresh).
CREATE OR REPLACE FUNCTION list_saml_idps_with_metadata_url_unscoped()
RETURNS TABLE (
    id uuid,
    tenant_id uuid,
    name text,
    metadata_url text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT id, tenant_id, name, metadata_url
    FROM public.saml_identity_providers
    WHERE metadata_url IS NOT NULL
$$;

REVOKE ALL ON FUNCTION list_saml_idps_with_metadata_url_unscoped() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_saml_idps_with_metadata_url_unscoped() TO appuser;

-- 4. Tenants with an inactivity threshold (for idle-user auto-inactivation).
CREATE OR REPLACE FUNCTION list_tenants_with_inactivity_threshold_unscoped()
RETURNS TABLE (
    tenant_id uuid,
    inactivity_threshold_days integer
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT tenant_id, inactivity_threshold_days
    FROM public.tenant_security_settings
    WHERE inactivity_threshold_days IS NOT NULL
$$;

REVOKE ALL ON FUNCTION list_tenants_with_inactivity_threshold_unscoped() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_tenants_with_inactivity_threshold_unscoped() TO appuser;

RESET ROLE;
