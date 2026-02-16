-- Add SP attribute mapping columns to service_providers
-- sp_requested_attributes: structured list from SP metadata RequestedAttribute elements
-- attribute_mapping: admin-controlled mapping of IdP attrs to SP-specific URIs

BEGIN;
SET LOCAL ROLE appowner;

ALTER TABLE service_providers
    ADD COLUMN IF NOT EXISTS sp_requested_attributes JSONB,
    ADD COLUMN IF NOT EXISTS attribute_mapping JSONB;

COMMENT ON COLUMN service_providers.sp_requested_attributes IS
    'SP-declared requested attributes from metadata (read-only). Format: [{"name": "urn:...", "friendly_name": "mail", "is_required": true}, ...]';

COMMENT ON COLUMN service_providers.attribute_mapping IS
    'Admin-controlled mapping of IdP attribute keys to SP-expected URIs. Format: {"email": "sp_uri", ...}. NULL means use global defaults.';

COMMIT;
