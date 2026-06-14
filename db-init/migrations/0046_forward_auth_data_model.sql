-- migration-safety: ignore (generalizes sp_group_assignments grant table to
-- also reference proxy_apps; dual nullable FK + one-of CHECK, see below)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- protected_domains: domains a tenant registers to protect via forward auth
--
-- A protected domain is a real DNS domain (e.g. acme-corp.com) the operator
-- owns and wants to gate with WeftID's forward-auth authority. WeftID must be
-- reachable at a portal host under that domain (e.g. auth.acme-corp.com) to set
-- the per-domain forward-auth cookie. Ownership is proven via a DNS-TXT
-- challenge before the domain becomes 'verified' (see iteration 2).
-- ---------------------------------------------------------------------------

CREATE TABLE protected_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The protected domain itself, e.g. "acme-corp.com".
    domain VARCHAR(253) NOT NULL,
    -- The WeftID portal host under that domain, e.g. "auth.acme-corp.com".
    portal_host VARCHAR(253) NOT NULL,
    -- Ownership / verification state machine. 'pending' until the DNS-TXT
    -- challenge is verified; 'verified' admits the host for certs + cookies.
    verification_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- DNS-TXT challenge token the operator must publish to prove control.
    verification_token VARCHAR(100),
    verified_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_protected_domains_tenant_domain UNIQUE (tenant_id, domain),
    CONSTRAINT chk_protected_domains_domain_length
        CHECK (length(domain) <= 253),
    CONSTRAINT chk_protected_domains_portal_host_length
        CHECK (length(portal_host) <= 253),
    CONSTRAINT chk_protected_domains_verification_status
        CHECK (verification_status IN ('pending', 'verified', 'failed')),
    CONSTRAINT chk_protected_domains_verification_token_length
        CHECK (verification_token IS NULL OR length(verification_token) <= 100)
);

CREATE INDEX idx_protected_domains_tenant
    ON protected_domains (tenant_id);
-- Cheap indexed lookup for the (pre-auth) ask endpoint + tenant resolution:
-- which tenant owns a given verified portal host.
CREATE UNIQUE INDEX uq_protected_domains_portal_host
    ON protected_domains (portal_host);

ALTER TABLE protected_domains ENABLE ROW LEVEL SECURITY;

CREATE POLICY protected_domains_tenant_isolation
    ON protected_domains
    FOR ALL
    TO appuser
    USING (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid)
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON protected_domains TO appuser;

CREATE TRIGGER trg_protected_domains_updated_at
    BEFORE UPDATE ON protected_domains
    FOR EACH ROW
    EXECUTE FUNCTION update_service_providers_updated_at();

-- ---------------------------------------------------------------------------
-- proxy_apps: an HTTP app behind a protected domain, gated by forward auth
--
-- Each proxy app lives under exactly one protected domain. The external URL
-- pattern is the public address of the app (e.g. https://grafana.acme-corp.com).
-- public_paths and header_config are JSONB (mirrors
-- service_providers.attribute_mapping). Validation lives in the service layer.
-- ---------------------------------------------------------------------------

CREATE TABLE proxy_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    protected_domain_id UUID NOT NULL REFERENCES protected_domains(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    -- Public external URL pattern of the app, e.g. "https://grafana.acme-corp.com".
    external_url VARCHAR(2048) NOT NULL,
    -- Paths that bypass auth (login pages, health checks, static assets).
    -- JSONB array of rooted relative patterns, e.g. ["/health", "/public/*"].
    public_paths JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Which X-Forwarded-* identity headers to emit on allow, e.g.
    -- {"user": true, "email": true, "groups": false, "display_name": true}.
    header_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- If true, every authenticated tenant user can access (no grant needed).
    available_to_all BOOLEAN NOT NULL DEFAULT false,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_proxy_apps_name_length
        CHECK (length(name) <= 255),
    CONSTRAINT chk_proxy_apps_description_length
        CHECK (description IS NULL OR length(description) <= 2000),
    CONSTRAINT chk_proxy_apps_external_url_length
        CHECK (length(external_url) <= 2048)
);

CREATE INDEX idx_proxy_apps_tenant
    ON proxy_apps (tenant_id);
CREATE INDEX idx_proxy_apps_protected_domain
    ON proxy_apps (protected_domain_id);

ALTER TABLE proxy_apps ENABLE ROW LEVEL SECURITY;

CREATE POLICY proxy_apps_tenant_isolation
    ON proxy_apps
    FOR ALL
    TO appuser
    USING (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid)
    WITH CHECK (tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON proxy_apps TO appuser;

CREATE TRIGGER trg_proxy_apps_updated_at
    BEFORE UPDATE ON proxy_apps
    FOR EACH ROW
    EXECUTE FUNCTION update_service_providers_updated_at();

-- ---------------------------------------------------------------------------
-- Generalize sp_group_assignments: dual nullable FK, one-of CHECK
--
-- The grant table now serves both SAML service providers and proxy apps via
-- two nullable FK columns. The populated column is the discriminator; there is
-- NO app_kind column. Existing SAML rows (sp_id set, proxy_app_id null) are
-- untouched and still CASCADE-delete with their SP.
--
-- Steps, ordered so the live table is never in an invalid state:
--   1. Add nullable proxy_app_id (FK + CASCADE).
--   2. Drop NOT NULL on sp_id (so proxy-app grants can leave it null).
--   3. Add the one-of CHECK. All existing rows satisfy it (sp_id set,
--      proxy_app_id null => exactly one populated).
--   4. Replace the (sp_id, group_id) unique constraint with two partial
--      unique indexes so each parent kind keeps its own uniqueness while
--      allowing nulls in the other column.
-- ---------------------------------------------------------------------------

ALTER TABLE sp_group_assignments
    ADD COLUMN proxy_app_id UUID REFERENCES proxy_apps(id) ON DELETE CASCADE;

ALTER TABLE sp_group_assignments
    ALTER COLUMN sp_id DROP NOT NULL;

ALTER TABLE sp_group_assignments
    ADD CONSTRAINT chk_sp_group_assignments_one_parent
        CHECK ((sp_id IS NOT NULL) <> (proxy_app_id IS NOT NULL));

-- The old (sp_id, group_id) unique constraint cannot express uniqueness for
-- proxy-app grants. Replace it with two partial unique indexes, one per kind.
ALTER TABLE sp_group_assignments
    DROP CONSTRAINT uq_sp_group_assignment;

CREATE UNIQUE INDEX uq_sp_group_assignment
    ON sp_group_assignments (sp_id, group_id)
    WHERE sp_id IS NOT NULL;

CREATE UNIQUE INDEX uq_proxy_app_group_assignment
    ON sp_group_assignments (proxy_app_id, group_id)
    WHERE proxy_app_id IS NOT NULL;

CREATE INDEX idx_sp_group_assignments_tenant_proxy_app
    ON sp_group_assignments (tenant_id, proxy_app_id)
    WHERE proxy_app_id IS NOT NULL;
