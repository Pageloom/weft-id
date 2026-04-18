SET LOCAL ROLE appowner;

ALTER TABLE tenant_security_settings
    ADD COLUMN required_auth_strength VARCHAR(20) NOT NULL DEFAULT 'baseline'
        CHECK (required_auth_strength IN ('baseline','enhanced'));
