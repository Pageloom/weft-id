SET LOCAL ROLE appowner;

ALTER TABLE tenant_security_settings
    ADD COLUMN IF NOT EXISTS minimum_password_length integer DEFAULT 14 NOT NULL;

ALTER TABLE tenant_security_settings
    ADD COLUMN IF NOT EXISTS minimum_zxcvbn_score integer DEFAULT 3 NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_minimum_password_length'
    ) THEN
        ALTER TABLE tenant_security_settings
            ADD CONSTRAINT chk_minimum_password_length
            CHECK (minimum_password_length IN (8, 10, 12, 14, 16, 18, 20));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_minimum_zxcvbn_score'
    ) THEN
        ALTER TABLE tenant_security_settings
            ADD CONSTRAINT chk_minimum_zxcvbn_score
            CHECK (minimum_zxcvbn_score IN (3, 4));
    END IF;
END $$;
