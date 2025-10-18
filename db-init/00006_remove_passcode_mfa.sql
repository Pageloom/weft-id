-- Migration: Remove Password Manager (TOTP) flow, keep only Authenticator App
-- Disable MFA for users who have 'passcode' method set (they'll need to re-setup with Authenticator App)

-- Disable MFA for users with passcode method
UPDATE users
SET mfa_enabled = false,
    mfa_method = NULL
WHERE mfa_method = 'passcode';

-- Delete TOTP secrets for passcode method (cleanup)
DELETE FROM mfa_totp
WHERE method = 'passcode';

-- Add comment to document allowed values for mfa_method
COMMENT ON COLUMN users.mfa_method IS 'MFA method: totp (Authenticator App) or email. NULL if MFA disabled.';
COMMENT ON COLUMN mfa_totp.method IS 'TOTP method: should only be ''totp'' for Authenticator App';
