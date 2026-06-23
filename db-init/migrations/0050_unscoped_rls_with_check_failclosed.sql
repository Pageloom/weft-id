-- Fail closed on UNSCOPED writes: tighten WITH CHECK on the widened RLS policies.
--
-- Migrations 0037 (scim_push_queue, scim_sync_log, sp_scim_credentials),
-- 0045 (scim_inbound_tokens), 0047 (protected_domains), and 0048
-- (forward_auth_nonces) all widened their tenant-isolation policy so a
-- pre-auth or background path could READ a row before the request tenant
-- is established. They did this with a CASE whose first branch returns
-- `true` when `app.tenant_id` is unset/empty.
--
-- The flaw: that same permissive branch was copied verbatim into WITH CHECK.
-- WITH CHECK governs the NEW row of an INSERT/UPDATE, so under UNSCOPED
-- (no app.tenant_id) a write could stamp an ARBITRARY tenant_id and RLS
-- would allow it instead of failing closed. It is safe today only because
-- every UNSCOPED path on these tables is read-only or DELETE-only (DELETE
-- is gated by USING, not WITH CHECK). This is a latent defense-in-depth gap:
-- a future UNSCOPED INSERT/UPDATE would silently bypass tenant isolation.
--
-- Fix: keep USING permissive (reads must still resolve the row pre-scope),
-- but make WITH CHECK strict so an UNSCOPED write fails closed. The strict
-- form mirrors the baseline schema and the service_providers policy that
-- 0040 already reverted to strict: when app.tenant_id is unset/empty the
-- NULLIF yields NULL, NULL::uuid is NULL, and `tenant_id = NULL` is NULL
-- (rejected). Legitimate scoped writes (mint paths) are unaffected.
--
-- NOT touched here:
--   * service_providers -- already strict (0040 reverted 0037's widening and
--     routed the cleanup scan through a SECURITY DEFINER function).
--   * event_logs -- intentionally keeps a permissive WITH CHECK: the PII
--     redaction job UPDATEs assertion events UNSCOPED (cross-tenant), so its
--     writes legitimately run without a tenant scope. The compliance scanner
--     added alongside this migration exempts it for that reason.
--
-- ALTER POLICY changes only the WITH CHECK expression, leaving USING (and
-- FOR/TO) intact. The migrate connection is the postgres superuser, which
-- can alter policies on any table regardless of owner (the SCIM tables from
-- 0036 are postgres-owned; the rest are appowner-owned), so no SET LOCAL
-- ROLE is needed -- this mirrors how 0037 managed both ownerships.

ALTER POLICY scim_push_queue_tenant_isolation ON scim_push_queue
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

ALTER POLICY scim_sync_log_tenant_isolation ON scim_sync_log
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

ALTER POLICY sp_scim_credentials_tenant_isolation ON sp_scim_credentials
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

ALTER POLICY scim_inbound_tokens_tenant_isolation ON scim_inbound_tokens
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

ALTER POLICY protected_domains_tenant_isolation ON protected_domains
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

ALTER POLICY forward_auth_nonces_tenant_isolation ON forward_auth_nonces
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);
