-- Add per-SP assertion encryption algorithm selection (CBC vs GCM)
SET LOCAL ROLE appowner;

ALTER TABLE service_providers
    ADD COLUMN assertion_encryption_algorithm VARCHAR(20)
    NOT NULL DEFAULT 'aes256-cbc'
    CHECK (assertion_encryption_algorithm IN ('aes256-cbc', 'aes256-gcm'));
