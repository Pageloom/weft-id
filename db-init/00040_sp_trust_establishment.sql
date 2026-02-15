-- 00040: SP Trust Establishment
-- Allow creating SPs with just a name (no entity_id/acs_url) and
-- establish trust later when the SP's metadata becomes available.

BEGIN;
SET LOCAL ROLE appowner;

-- Allow NULL entity_id and acs_url for pending (pre-trust) SPs
ALTER TABLE service_providers ALTER COLUMN entity_id DROP NOT NULL;
ALTER TABLE service_providers ALTER COLUMN acs_url DROP NOT NULL;

-- Track whether trust has been established with the SP
ALTER TABLE service_providers ADD COLUMN trust_established BOOLEAN NOT NULL DEFAULT false;

-- Backfill: all existing SPs have trust established (they have entity_id + acs_url)
UPDATE service_providers SET trust_established = true WHERE entity_id IS NOT NULL;

COMMIT;
