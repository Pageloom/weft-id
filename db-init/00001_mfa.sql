-- ============================================================================
-- Multi-Factor Authentication (MFA) Tables
-- ============================================================================
\set ON_ERROR_STOP on

-- Add MFA columns to users table
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM information_schema.columns
                       WHERE table_schema = 'public'
                         AND table_name = 'users'
                         AND column_name = 'mfa_enabled') THEN
            ALTER TABLE users
                ADD COLUMN mfa_enabled BOOLEAN DEFAULT false,
                ADD COLUMN mfa_method TEXT NULL CHECK (mfa_method IN ('passcode', 'totp', 'email'));
        END IF;
    END
$$;

-- TOTP/Passcode secrets (both use TOTP protocol but different UX)
CREATE TABLE IF NOT EXISTS mfa_totp
(
    id               UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL,
    user_id          UUID        NOT NULL,
    secret_encrypted TEXT        NOT NULL,
    method           TEXT        NOT NULL CHECK (method IN ('passcode', 'totp')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at      TIMESTAMPTZ NULL,

    CONSTRAINT fk_mfa_totp_user_tenant
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE CASCADE,

    UNIQUE (user_id, method)
);

COMMENT ON TABLE mfa_totp IS 'TOTP secrets for both passcode and classic TOTP methods';
COMMENT ON COLUMN mfa_totp.method IS 'passcode (password manager) or totp (authenticator app)';
COMMENT ON COLUMN mfa_totp.verified_at IS 'when user completed setup verification';

-- Email OTP codes (fallback)
CREATE TABLE IF NOT EXISTS mfa_email_codes
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL,
    user_id    UUID        NOT NULL,
    code_hash  TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_mfa_email_codes_user_tenant
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE mfa_email_codes IS 'Temporary email OTP codes with expiration';

-- Backup codes (for recovery)
CREATE TABLE IF NOT EXISTS mfa_backup_codes
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL,
    user_id    UUID        NOT NULL,
    code_hash  TEXT        NOT NULL,
    used_at    TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_mfa_backup_codes_user_tenant
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE mfa_backup_codes IS 'Single-use backup codes for account recovery';

-- ============================================================================
-- INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_mfa_totp_user ON mfa_totp (user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_email_codes_user_expires ON mfa_email_codes (user_id, expires_at)
    WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes (user_id)
    WHERE used_at IS NULL;

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

-- Enable RLS on mfa_totp
ALTER TABLE mfa_totp ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'mfa_totp'
                         AND policyname = 'mfa_totp_tenant_isolation') THEN
            CREATE POLICY mfa_totp_tenant_isolation ON mfa_totp
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

-- Enable RLS on mfa_email_codes
ALTER TABLE mfa_email_codes ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'mfa_email_codes'
                         AND policyname = 'mfa_email_codes_tenant_isolation') THEN
            CREATE POLICY mfa_email_codes_tenant_isolation ON mfa_email_codes
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

-- Enable RLS on mfa_backup_codes
ALTER TABLE mfa_backup_codes ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'mfa_backup_codes'
                         AND policyname = 'mfa_backup_codes_tenant_isolation') THEN
            CREATE POLICY mfa_backup_codes_tenant_isolation ON mfa_backup_codes
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE mfa_totp TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE mfa_email_codes TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE mfa_backup_codes TO appuser;
