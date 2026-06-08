-- Allow UNSCOPED reads on scim_inbound_tokens for the bearer-auth path.
--
-- The inbound SCIM bearer-auth dependency (`require_inbound_scim_auth` in
-- `app/api_dependencies.py`) must look a token up by its SHA-256 hash
-- BEFORE the request tenant is known -- the token row's `tenant_id` is
-- what establishes the request scope. It therefore queries with
-- `database.UNSCOPED` (no `app.tenant_id` set).
--
-- The original 0042 policy used strict isolation
-- (`tenant_id = current_setting('app.tenant_id', true)::uuid`) with no
-- escape hatch for the unset setting. With no `app.tenant_id`, the cast
-- of the empty string yields NULL, so the row is invisible and EVERY
-- authenticated inbound SCIM request (read and write) fails with 401.
-- The globally-unique `token_hash` index already prevents the cross-tenant
-- collision risk that UNSCOPED lookups would otherwise carry.
--
-- This mirrors the `0037_scim_unscoped_rls` pattern: when the setting is
-- unset or empty, all rows are visible (the auth path then immediately
-- re-scopes to the token's tenant); when set, only the scoped tenant's
-- rows are visible.
--
-- The table is owned by appowner (created under SET LOCAL ROLE appowner in
-- 0042), so manage the policy with appowner ownership.

SET LOCAL ROLE appowner;

DROP POLICY IF EXISTS scim_inbound_tokens_tenant_isolation ON scim_inbound_tokens;
CREATE POLICY scim_inbound_tokens_tenant_isolation
    ON scim_inbound_tokens
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
