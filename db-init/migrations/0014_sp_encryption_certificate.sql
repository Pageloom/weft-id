-- Add encryption certificate support for downstream SPs.
-- When an SP advertises an encryption certificate in its metadata,
-- WeftId encrypts SAML assertions so only the SP can read them.
SET LOCAL ROLE appowner;

ALTER TABLE service_providers
    ADD COLUMN encryption_certificate_pem TEXT;

ALTER TABLE service_providers
    ADD CONSTRAINT service_providers_encryption_certificate_pem_length
        CHECK (length(encryption_certificate_pem) <= 16000);
