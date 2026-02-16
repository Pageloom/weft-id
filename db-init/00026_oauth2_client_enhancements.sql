-- ============================================================================
-- OAuth2 Client Enhancements
--
-- Adds columns to oauth2_clients for the Integration Management UI:
--   - description: Optional text description for the client
--   - is_active: Soft-delete flag (prep for Phase 2 deactivation)
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- ALTER TABLE: oauth2_clients
-- Add description and is_active columns
-- ============================================================================

ALTER TABLE oauth2_clients
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN oauth2_clients.description IS
    'Optional description of the OAuth2 client.';

COMMENT ON COLUMN oauth2_clients.is_active IS
    'Whether the client is active. Inactive clients cannot authenticate.';

COMMIT;
