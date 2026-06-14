-- Allow UNSCOPED reads on protected_domains for the pre-auth infra paths.
--
-- The Caddy on-demand-TLS ask endpoint (`GET /caddy/check-domain` in
-- `app/routers/health.py`) and `TenantGuardMiddleware` must resolve a
-- forward-auth portal host to its owning tenant BEFORE the request tenant is
-- known -- the portal host is what establishes the scope. They therefore look
-- the row up with `database.UNSCOPED` (no `app.tenant_id` set).
--
-- The original 0046 policy used strict isolation
-- (`tenant_id = current_setting('app.tenant_id', true)::uuid`) with no escape
-- hatch for the unset setting. With no `app.tenant_id`, the cast of the empty
-- string yields NULL, so every row is invisible and the UNSCOPED portal-host
-- lookup returns nothing. The globally-unique `uq_protected_domains_portal_host`
-- index already prevents the cross-tenant collision risk that UNSCOPED lookups
-- would otherwise carry, and the service only admits VERIFIED, ENABLED rows.
--
-- This mirrors the `0045_scim_inbound_tokens_unscoped_rls` pattern: when the
-- setting is unset or empty, all rows are visible (callers then immediately
-- re-scope to the row's tenant); when set, only the scoped tenant's rows are
-- visible. Normal tenant-scoped CRUD is unaffected.
--
-- The table is owned by appowner (created under SET LOCAL ROLE appowner in
-- 0046), so manage the policy with appowner ownership.

SET LOCAL ROLE appowner;

DROP POLICY IF EXISTS protected_domains_tenant_isolation ON protected_domains;
CREATE POLICY protected_domains_tenant_isolation
    ON protected_domains
    FOR ALL
    TO appuser
    USING (
        CASE
            WHEN (NULLIF(current_setting('app.tenant_id', true), '') IS NULL) THEN true
            ELSE (tenant_id = current_setting('app.tenant_id', true)::uuid)
        END)
    WITH CHECK (
        CASE
            WHEN (NULLIF(current_setting('app.tenant_id', true), '') IS NULL) THEN true
            ELSE (tenant_id = current_setting('app.tenant_id', true)::uuid)
        END);
