-- Drop the mfa_email_codes table. Email OTP verification now uses stateless
-- HMAC time-windowed codes (via utils/tokens.py) with no database storage.
-- migration-safety: ignore

SET LOCAL ROLE appowner;

DROP TABLE IF EXISTS mfa_email_codes;
