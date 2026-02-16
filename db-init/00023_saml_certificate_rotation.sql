-- ============================================================================
-- SAML SP Certificate Rotation Support
--
-- This migration adds columns to support certificate rotation with grace period:
--   - previous_certificate_pem: The previous certificate (kept for grace period)
--   - previous_private_key_pem_enc: The previous private key (encrypted)
--   - previous_expires_at: Expiry of the previous certificate
--   - rotation_grace_period_ends_at: When the grace period ends
--
-- During a rotation:
--   1. New certificate is generated
--   2. Current certificate moves to previous_* columns
--   3. Grace period is set (default 7 days)
--   4. Both certificates are valid during grace period
--   5. After grace period, previous_* columns can be cleared
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- ALTER TABLE: saml_sp_certificates
-- Add columns for previous certificate storage
-- ============================================================================

ALTER TABLE saml_sp_certificates
    ADD COLUMN IF NOT EXISTS previous_certificate_pem TEXT,
    ADD COLUMN IF NOT EXISTS previous_private_key_pem_enc TEXT,
    ADD COLUMN IF NOT EXISTS previous_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rotation_grace_period_ends_at TIMESTAMPTZ;

COMMENT ON COLUMN saml_sp_certificates.previous_certificate_pem IS
    'Previous certificate kept during rotation grace period. Both certs are valid.';

COMMENT ON COLUMN saml_sp_certificates.previous_private_key_pem_enc IS
    'Fernet-encrypted private key for the previous certificate.';

COMMENT ON COLUMN saml_sp_certificates.previous_expires_at IS
    'Original expiry date of the previous certificate.';

COMMENT ON COLUMN saml_sp_certificates.rotation_grace_period_ends_at IS
    'When the grace period ends. After this, previous cert can be cleared.';

COMMIT;
