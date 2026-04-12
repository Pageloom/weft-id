-- Allow UNSCOPED access to event_logs for background worker jobs.
--
-- The PII redaction job needs cross-tenant access to find and update
-- verbose assertion events. This follows the same CASE-based pattern
-- used by export_files.
SET LOCAL ROLE appowner;

-- Drop the existing strict policy
DROP POLICY event_logs_tenant_isolation ON event_logs;

-- Create a new policy that allows UNSCOPED access (when app.tenant_id
-- is not set or empty, all rows are visible). When set, only rows
-- matching the tenant are visible.
CREATE POLICY event_logs_tenant_isolation ON event_logs
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
