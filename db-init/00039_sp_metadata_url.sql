-- Add metadata_url column to service_providers
-- Stores the URL from which SP metadata was originally imported,
-- enabling refresh/re-fetch workflows.

BEGIN;
SET LOCAL ROLE appowner;

ALTER TABLE service_providers
    ADD COLUMN IF NOT EXISTS metadata_url TEXT;

COMMENT ON COLUMN service_providers.metadata_url IS
    'Source URL from which SP metadata was imported (nullable, only set for URL imports)';

COMMIT;
