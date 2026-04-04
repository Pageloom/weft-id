SET LOCAL ROLE appowner;

ALTER TABLE tenant_security_settings
    ADD COLUMN require_email_verification_for_login boolean NOT NULL DEFAULT false;
