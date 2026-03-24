-- Add pre-rasterized PNG column for email logo embedding.
-- Emails need PNG (not SVG) because major email clients strip SVGs.
-- This column is populated at logo save time so emails never need
-- runtime SVG-to-PNG conversion.

SET LOCAL ROLE appowner;

ALTER TABLE tenant_branding
    ADD COLUMN logo_email_png BYTEA;

-- Backfill: copy existing PNG light logos into the new column.
-- SVG logos and default mandalas are backfilled by the application
-- on first email send (one-time lazy rasterization).
UPDATE tenant_branding
   SET logo_email_png = logo_light
 WHERE logo_light IS NOT NULL
   AND logo_light_mime = 'image/png';
