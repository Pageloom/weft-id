SET LOCAL ROLE appowner;

-- Add verbose assertion logging toggle to SAML identity providers.
-- NULL = off. Non-NULL timestamp = enabled at that time.
-- Active check: enabled_at > now() - interval '24 hours'.
ALTER TABLE saml_identity_providers
    ADD COLUMN verbose_logging_enabled_at TIMESTAMPTZ;
