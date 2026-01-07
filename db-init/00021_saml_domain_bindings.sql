-- Migration 00021: SAML Domain Bindings and User Auth Method
--
-- Adds:
-- 1. saml_idp_domain_bindings table - links privileged domains to SAML IdPs
-- 2. auth_method column on users - for "password only" override
--
-- Security model:
-- - Each privileged domain can be bound to at most one IdP
-- - Users with bound domains are routed to that IdP
-- - Users can be set to "password_only" to bypass SAML routing

-- =============================================================================
-- Domain-to-IdP Binding Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS saml_idp_domain_bindings
(
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    domain_id  UUID        NOT NULL REFERENCES tenant_privileged_domains (id) ON DELETE CASCADE,
    idp_id     UUID        NOT NULL REFERENCES saml_identity_providers (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID        NOT NULL,

    -- Each domain can only be bound to ONE IdP per tenant
    CONSTRAINT uq_saml_domain_binding UNIQUE (tenant_id, domain_id),

    -- Foreign key to the user who created this binding
    CONSTRAINT fk_saml_domain_binding_created_by
        FOREIGN KEY (created_by, tenant_id)
            REFERENCES users (id, tenant_id)
            ON DELETE SET NULL
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_saml_domain_bindings_tenant
    ON saml_idp_domain_bindings (tenant_id);

CREATE INDEX IF NOT EXISTS idx_saml_domain_bindings_domain
    ON saml_idp_domain_bindings (domain_id);

CREATE INDEX IF NOT EXISTS idx_saml_domain_bindings_idp
    ON saml_idp_domain_bindings (idp_id);

-- Enable Row Level Security
ALTER TABLE saml_idp_domain_bindings ENABLE ROW LEVEL SECURITY;

-- RLS Policy for tenant isolation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'saml_idp_domain_bindings'
        AND policyname = 'saml_domain_bindings_isolation'
    ) THEN
        CREATE POLICY saml_domain_bindings_isolation ON saml_idp_domain_bindings
            USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
    END IF;
END $$;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE saml_idp_domain_bindings TO appuser;

-- =============================================================================
-- User Auth Method Column
-- =============================================================================

-- Add auth_method column to users table
-- Values:
--   'automatic' (default): Use routing priority (user IdP -> domain -> default -> password)
--   'password_only': Force password authentication, ignore SAML routing
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'auth_method'
    ) THEN
        ALTER TABLE users
            ADD COLUMN auth_method TEXT
            CHECK (auth_method IN ('automatic', 'password_only'))
            DEFAULT 'automatic';
    END IF;
END $$;

-- Set default for any existing users without auth_method
UPDATE users SET auth_method = 'automatic' WHERE auth_method IS NULL;

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE saml_idp_domain_bindings IS
    'Links privileged email domains to SAML Identity Providers for automatic routing';

COMMENT ON COLUMN saml_idp_domain_bindings.domain_id IS
    'Reference to tenant_privileged_domains - the email domain to route';

COMMENT ON COLUMN saml_idp_domain_bindings.idp_id IS
    'Reference to saml_identity_providers - the IdP to route users to';

COMMENT ON COLUMN users.auth_method IS
    'Authentication method override: automatic (use routing) or password_only (bypass SAML)';
