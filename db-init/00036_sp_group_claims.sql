-- Add include_group_claims toggle to service_providers
-- When enabled, SAML assertions include user's group memberships as a multi-valued attribute

BEGIN;
SET LOCAL ROLE appowner;

ALTER TABLE service_providers
    ADD COLUMN include_group_claims BOOLEAN NOT NULL DEFAULT false;

COMMIT;
