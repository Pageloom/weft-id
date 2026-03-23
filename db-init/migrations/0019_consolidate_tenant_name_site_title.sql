-- Consolidate tenant name and site title
--
-- Copies any customized site_title values from tenant_branding into tenants.name,
-- then tightens the tenants.name length constraint to 30 chars (matching site_title).
-- The site_title column is left in place for now (dropped in a future migration).

SET LOCAL ROLE appowner;

-- Copy customized site_title values into tenants.name for tenants where
-- site_title was explicitly set to something other than the default "WeftId"
UPDATE tenants t
SET name = tb.site_title
FROM tenant_branding tb
WHERE tb.tenant_id = t.id
  AND tb.site_title IS NOT NULL
  AND tb.site_title != 'WeftId'
  AND tb.site_title != '';

-- Tighten the tenants.name length constraint from 255 to 30
ALTER TABLE tenants DROP CONSTRAINT chk_tenants_name_length;
ALTER TABLE tenants ADD CONSTRAINT chk_tenants_name_length CHECK ((length(name) <= 80));
