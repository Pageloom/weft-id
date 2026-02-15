\set ON_ERROR_STOP on
SET LOCAL ROLE appowner;

ALTER TABLE tenant_security_settings
    ADD COLUMN max_certificate_lifetime_years INTEGER NOT NULL DEFAULT 10;

ALTER TABLE tenant_security_settings
    ADD CONSTRAINT chk_certificate_lifetime_years
    CHECK (max_certificate_lifetime_years IN (1, 2, 3, 5, 10));

COMMENT ON COLUMN tenant_security_settings.max_certificate_lifetime_years
    IS 'Maximum lifetime in years for newly generated signing certificates';
