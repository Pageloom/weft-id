-- ============================================================================
-- Add theme column to users table for dark mode preference
-- ============================================================================
\set ON_ERROR_STOP on

-- Add theme column: 'system' (default), 'light', or 'dark'
-- System means follow OS preference via prefers-color-scheme
ALTER TABLE users ADD COLUMN IF NOT EXISTS theme TEXT DEFAULT 'system'
    CHECK (theme IN ('system', 'light', 'dark'));

COMMENT ON COLUMN users.theme IS 'User theme preference: system (follow OS), light, or dark';
