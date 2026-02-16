-- ============================================================================
-- OAuth2 Infrastructure
--
-- This migration implements OAuth2 authentication infrastructure to support
-- RESTful API access with three authentication methods:
--   - Session cookies (existing, unchanged)
--   - OAuth2 Authorization Code Flow (user-delegated API access)
--   - OAuth2 Client Credentials Flow (B2B integrations)
--
-- All tokens are opaque (not JWTs) and database-backed for instant revocation.
--
-- Changes:
--   1) oauth2_clients table - OAuth2 client registration (normal & B2B)
--   2) oauth2_authorization_codes table - Short-lived auth codes with PKCE
--   3) oauth2_tokens table - Access and refresh tokens
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- TABLES
-- ============================================================================

-- OAuth2 Clients (Normal and B2B)
CREATE TABLE IF NOT EXISTS oauth2_clients
(
    id                 UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id          TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT        NOT NULL,
    client_type        TEXT        NOT NULL CHECK (client_type IN ('normal', 'b2b')),
    name               TEXT        NOT NULL,
    redirect_uris      TEXT[],
    service_user_id    UUID REFERENCES users (id) ON DELETE RESTRICT,
    created_by         UUID        NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_created_by_user
        FOREIGN KEY (created_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL
);

COMMENT ON TABLE oauth2_clients IS
    'OAuth2 client registrations. Normal clients use authorization code flow, B2B clients use client credentials flow with service users.';

COMMENT ON COLUMN oauth2_clients.client_id IS
    'Public client identifier (e.g., "loom_client_abc123")';

COMMENT ON COLUMN oauth2_clients.client_secret_hash IS
    'Argon2 hash of client secret (never store plain text)';

COMMENT ON COLUMN oauth2_clients.client_type IS
    'Client type: "normal" for authorization code flow, "b2b" for client credentials flow';

COMMENT ON COLUMN oauth2_clients.redirect_uris IS
    'Array of exact redirect URIs (normal clients only, NULL for B2B)';

COMMENT ON COLUMN oauth2_clients.service_user_id IS
    'Service user for B2B clients (NULL for normal clients). Deletion is RESTRICTED to force explicit cleanup.';

-- OAuth2 Authorization Codes (for Authorization Code Flow)
CREATE TABLE IF NOT EXISTS oauth2_authorization_codes
(
    id                      UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id               UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    code_hash               TEXT UNIQUE NOT NULL,
    client_id               UUID        NOT NULL REFERENCES oauth2_clients (id) ON DELETE CASCADE,
    user_id                 UUID        NOT NULL,
    redirect_uri            TEXT        NOT NULL,
    code_challenge          TEXT,
    code_challenge_method   TEXT CHECK (code_challenge_method IN ('S256', 'plain')),
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_user
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE oauth2_authorization_codes IS
    'Short-lived authorization codes (5 min expiry) for OAuth2 authorization code flow. One-time use only.';

COMMENT ON COLUMN oauth2_authorization_codes.code_hash IS
    'Argon2 hash of authorization code (never store plain text)';

COMMENT ON COLUMN oauth2_authorization_codes.code_challenge IS
    'PKCE code challenge (optional, for public clients)';

COMMENT ON COLUMN oauth2_authorization_codes.code_challenge_method IS
    'PKCE challenge method: "S256" (SHA-256) or "plain"';

-- OAuth2 Tokens (Access and Refresh Tokens)
CREATE TABLE IF NOT EXISTS oauth2_tokens
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    token_hash      TEXT UNIQUE NOT NULL,
    token_type      TEXT        NOT NULL CHECK (token_type IN ('access', 'refresh')),
    client_id       UUID        NOT NULL REFERENCES oauth2_clients (id) ON DELETE CASCADE,
    user_id         UUID        NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    parent_token_id UUID REFERENCES oauth2_tokens (id) ON DELETE CASCADE,

    CONSTRAINT fk_user
        FOREIGN KEY (user_id, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE oauth2_tokens IS
    'OAuth2 access and refresh tokens. Opaque tokens (not JWTs) for instant revocation capability.';

COMMENT ON COLUMN oauth2_tokens.token_hash IS
    'Argon2 hash of opaque token (never store plain text)';

COMMENT ON COLUMN oauth2_tokens.token_type IS
    'Token type: "access" or "refresh"';

COMMENT ON COLUMN oauth2_tokens.parent_token_id IS
    'For access tokens, links to the refresh token that created it (enables cascade revocation)';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- oauth2_clients indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_tenant
    ON oauth2_clients (tenant_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_clients_service_user
    ON oauth2_clients (service_user_id)
    WHERE service_user_id IS NOT NULL;

-- oauth2_authorization_codes indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_codes_tenant
    ON oauth2_authorization_codes (tenant_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_codes_expires
    ON oauth2_authorization_codes (expires_at);

-- oauth2_tokens indexes
CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_tenant
    ON oauth2_tokens (tenant_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_user
    ON oauth2_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_expires
    ON oauth2_tokens (expires_at);

CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_hash
    ON oauth2_tokens (token_hash);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE oauth2_clients TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE oauth2_authorization_codes TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE oauth2_tokens TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE oauth2_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth2_authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth2_tokens ENABLE ROW LEVEL SECURITY;

-- RLS policy for oauth2_clients
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'oauth2_clients'
                         AND policyname = 'oauth2_clients_tenant_isolation') THEN
            CREATE POLICY oauth2_clients_tenant_isolation ON oauth2_clients
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

-- RLS policy for oauth2_authorization_codes
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'oauth2_authorization_codes'
                         AND policyname = 'oauth2_codes_tenant_isolation') THEN
            CREATE POLICY oauth2_codes_tenant_isolation ON oauth2_authorization_codes
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

-- RLS policy for oauth2_tokens
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'oauth2_tokens'
                         AND policyname = 'oauth2_tokens_tenant_isolation') THEN
            CREATE POLICY oauth2_tokens_tenant_isolation ON oauth2_tokens
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

COMMIT;
