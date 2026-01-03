-- ============================================================================
-- Inactivity Threshold Settings
--
-- This migration adds support for automatic user inactivation based on
-- inactivity. Tenants can configure how many days of inactivity will
-- trigger automatic account inactivation.
--
-- Changes:
--   1) Add column to tenant_security_settings:
--      - inactivity_threshold_days (NULL = disabled, or 14/30/60/90 days)
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- ALTER TABLE
-- ============================================================================

ALTER TABLE tenant_security_settings
    ADD COLUMN IF NOT EXISTS inactivity_threshold_days INTEGER DEFAULT NULL
        CHECK (inactivity_threshold_days IS NULL OR inactivity_threshold_days > 0);

COMMENT ON COLUMN tenant_security_settings.inactivity_threshold_days IS
    'Number of days of inactivity before a user is automatically inactivated. NULL means disabled (no automatic inactivation). Common values: 14, 30, 60, 90.';
