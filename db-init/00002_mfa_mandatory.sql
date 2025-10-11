-- ============================================================================
-- Make MFA Mandatory - Email as Default
-- ============================================================================
\set ON_ERROR_STOP on

-- Set email MFA as default for new users
ALTER TABLE users
    ALTER COLUMN mfa_enabled SET DEFAULT true,
    ALTER COLUMN mfa_method SET DEFAULT 'email';

-- Enable email MFA for all existing users who don't have MFA
UPDATE users
SET mfa_enabled = true,
    mfa_method = 'email'
WHERE mfa_enabled = false OR mfa_enabled IS NULL;
