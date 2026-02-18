SET LOCAL ROLE appowner;

ALTER TABLE tenant_security_settings
    ADD COLUMN IF NOT EXISTS certificate_rotation_window_days integer DEFAULT 90 NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_certificate_rotation_window_days'
    ) THEN
        ALTER TABLE tenant_security_settings
            ADD CONSTRAINT chk_certificate_rotation_window_days
            CHECK (certificate_rotation_window_days IN (14, 30, 60, 90));
    END IF;
END $$;
