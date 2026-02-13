-- Add SLO URL column to service_providers for Single Logout support
SET LOCAL ROLE appowner;

ALTER TABLE service_providers
    ADD COLUMN slo_url TEXT;

COMMENT ON COLUMN service_providers.slo_url IS
    'Single Logout Service URL for the downstream SP. Extracted from metadata or manually entered.';
