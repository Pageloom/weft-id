-- Drop the unused site_title column from tenant_branding.
-- All code now uses tenants.name instead (consolidated in migration 0019).
-- migration-safety: ignore

SET LOCAL ROLE appowner;

ALTER TABLE tenant_branding DROP COLUMN IF EXISTS site_title;
