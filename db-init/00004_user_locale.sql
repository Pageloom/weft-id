-- ============================================================================
-- Add locale column to users table
-- ============================================================================
\set ON_ERROR_STOP on

-- Add locale column to store user's preferred locale (e.g., en_US, sv_SE, fr_FR)
ALTER TABLE users ADD COLUMN IF NOT EXISTS locale TEXT NULL CHECK (length(locale) <= 20);

COMMENT ON COLUMN users.locale IS 'User locale preference (e.g., en_US, sv_SE, fr_FR). Used for date/time formatting and future localization.';
