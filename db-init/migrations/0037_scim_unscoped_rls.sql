-- Allow UNSCOPED reads on outbound-SCIM tables for the background worker.
--
-- The push worker scans `scim_push_queue` cross-tenant to discover which
-- tenants have ready work, and the nightly cleanup job scans
-- `service_providers` cross-tenant to find every SCIM-enabled SP across
-- all tenants. Both run from a background context where no
-- `app.tenant_id` is set; the existing strict-isolation policies blow up
-- on the `''::uuid` cast.
--
-- This mirrors the `event_logs_unscoped_rls` pattern: when the setting is
-- unset or empty, all rows are visible (system task); when set, only the
-- scoped tenant's rows are visible.
--
-- The SCIM tables created by 0036 ended up owned by `postgres` rather
-- than `appowner` (a quirk of that migration's transaction). DROP POLICY
-- requires ownership, so we leave the role as the connection user
-- (postgres in dev/prod) rather than SET LOCAL ROLE appowner. The
-- service_providers table IS owned by appowner; the same connection
-- (postgres superuser) can manage policies on either.

DROP POLICY IF EXISTS scim_push_queue_tenant_isolation ON scim_push_queue;
CREATE POLICY scim_push_queue_tenant_isolation ON scim_push_queue
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

DROP POLICY IF EXISTS scim_sync_log_tenant_isolation ON scim_sync_log;
CREATE POLICY scim_sync_log_tenant_isolation ON scim_sync_log
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

DROP POLICY IF EXISTS sp_scim_credentials_tenant_isolation ON sp_scim_credentials;
CREATE POLICY sp_scim_credentials_tenant_isolation ON sp_scim_credentials
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

-- service_providers gains UNSCOPED-visible rows too. The cleanup job
-- needs to scan every SCIM-enabled SP across all tenants. The previous
-- NULLIF-only policy evaluates to NULL (i.e., false) when the setting
-- is unset, hiding every row from the background scan.
DROP POLICY IF EXISTS service_providers_tenant_isolation ON service_providers;
CREATE POLICY service_providers_tenant_isolation ON service_providers
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
