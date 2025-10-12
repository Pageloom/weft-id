-- ============================================================================
-- Add timezone column to users table
-- ============================================================================
\set ON_ERROR_STOP on

-- Add tz column to store user's timezone (IANA format)
ALTER TABLE users ADD COLUMN IF NOT EXISTS tz TEXT NULL CHECK (length(tz) <= 100);

COMMENT ON COLUMN users.tz IS 'User timezone in IANA format (e.g., America/New_York, Europe/London). Auto-detected and updated on sign-in.';
