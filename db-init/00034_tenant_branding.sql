-- ============================================================================
-- Tenant Branding
--
-- Stores per-tenant branding configuration: custom logo images (light/dark
-- variants), display mode (mandala vs custom), and favicon preferences.
-- One row per tenant, created lazily on first branding interaction.
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
SET LOCAL ROLE appowner;

-- ============================================================================
-- ENUM: logo_mode
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'logo_mode') THEN
        CREATE TYPE logo_mode AS ENUM ('mandala', 'custom');
    END IF;
END
$$;

-- ============================================================================
-- TABLE: tenant_branding
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenant_branding
(
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL UNIQUE REFERENCES tenants (id) ON DELETE CASCADE,
    logo_light          BYTEA,
    logo_light_mime     TEXT,
    logo_dark           BYTEA,
    logo_dark_mime      TEXT,
    logo_mode           logo_mode   NOT NULL DEFAULT 'mandala',
    use_logo_as_favicon BOOLEAN     NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Ensure mime type is set whenever logo data is present
    CONSTRAINT chk_logo_light_mime CHECK (
        (logo_light IS NULL AND logo_light_mime IS NULL) OR
        (logo_light IS NOT NULL AND logo_light_mime IS NOT NULL)
    ),
    CONSTRAINT chk_logo_dark_mime CHECK (
        (logo_dark IS NULL AND logo_dark_mime IS NULL) OR
        (logo_dark IS NOT NULL AND logo_dark_mime IS NOT NULL)
    ),
    -- Only allow known image MIME types
    CONSTRAINT chk_logo_light_mime_valid CHECK (
        logo_light_mime IS NULL OR logo_light_mime IN ('image/png', 'image/svg+xml')
    ),
    CONSTRAINT chk_logo_dark_mime_valid CHECK (
        logo_dark_mime IS NULL OR logo_dark_mime IN ('image/png', 'image/svg+xml')
    )
);

COMMENT ON TABLE tenant_branding IS
    'Per-tenant branding configuration. One row per tenant, created on first interaction.';

COMMENT ON COLUMN tenant_branding.logo_light IS
    'Logo image bytes for light mode. NULL if no custom logo uploaded.';

COMMENT ON COLUMN tenant_branding.logo_dark IS
    'Logo image bytes for dark mode. NULL if no custom dark logo uploaded.';

COMMENT ON COLUMN tenant_branding.logo_mode IS
    'Whether to display the auto-generated mandala or a custom logo in navigation.';

COMMENT ON COLUMN tenant_branding.use_logo_as_favicon IS
    'When true and logo_mode is custom, use the light logo as the browser favicon.';


-- ============================================================================
-- INDEXES
-- ============================================================================

-- Tenant lookup (covered by UNIQUE constraint, explicit for clarity)
CREATE INDEX IF NOT EXISTS idx_tenant_branding_tenant
    ON tenant_branding (tenant_id);


-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_branding TO appuser;


-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'tenant_branding'
                         AND policyname = 'tenant_branding_tenant_isolation') THEN
            CREATE POLICY tenant_branding_tenant_isolation ON tenant_branding
                USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
                WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
        END IF;
    END
$$;
