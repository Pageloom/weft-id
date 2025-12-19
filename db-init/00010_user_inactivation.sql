-- ============================================================================
-- User Inactivation & GDPR Anonymization
--
-- This migration adds support for user inactivation (soft-disable login) and
-- GDPR anonymization (irreversible PII scrubbing).
--
-- Changes:
--   1) Add columns to users table:
--      - is_inactivated (boolean, default false) - user cannot sign in
--      - is_anonymized (boolean, default false) - PII has been scrubbed (irreversible)
--      - inactivated_at (timestamp) - when user was inactivated
--      - anonymized_at (timestamp) - when user was anonymized
--   2) Add constraint: anonymized users must also be inactivated
--   3) Add indexes for filtering inactivated/anonymized users
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- ALTER TABLE
-- ============================================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_inactivated BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS is_anonymized BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS inactivated_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS anonymized_at TIMESTAMPTZ NULL;

-- Constraint: anonymized implies inactivated
-- (An anonymized user must always be inactivated)
ALTER TABLE users ADD CONSTRAINT chk_anonymized_implies_inactivated
    CHECK (NOT is_anonymized OR is_inactivated);

COMMENT ON COLUMN users.is_inactivated IS
    'Whether the user account is inactivated. Inactivated users cannot sign in but retain all their data.';

COMMENT ON COLUMN users.is_anonymized IS
    'Whether the user has been anonymized (GDPR right to be forgotten). Anonymization is irreversible and scrubs all PII.';

COMMENT ON COLUMN users.inactivated_at IS
    'Timestamp when the user was inactivated. NULL if not inactivated.';

COMMENT ON COLUMN users.anonymized_at IS
    'Timestamp when the user was anonymized. NULL if not anonymized.';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Partial index for filtering inactivated users (only index rows where true)
CREATE INDEX IF NOT EXISTS idx_users_inactivated
    ON users (tenant_id, is_inactivated)
    WHERE is_inactivated = true;

-- Partial index for filtering anonymized users (only index rows where true)
CREATE INDEX IF NOT EXISTS idx_users_anonymized
    ON users (tenant_id, is_anonymized)
    WHERE is_anonymized = true;
