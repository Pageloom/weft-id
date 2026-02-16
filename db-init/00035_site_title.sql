-- Add custom site title and nav bar title visibility to tenant branding
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

ALTER TABLE tenant_branding ADD COLUMN IF NOT EXISTS site_title TEXT;
ALTER TABLE tenant_branding ADD COLUMN IF NOT EXISTS show_title_in_nav BOOLEAN NOT NULL DEFAULT true;

COMMIT;
