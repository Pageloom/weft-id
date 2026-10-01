-- migration-safety: ignore (both new tables are CREATEd in this same
-- migration, so they start empty and the index builds cannot block writers;
-- CONCURRENTLY is unnecessary and cannot run in-transaction. Dropping NOT NULL
-- on oauth2_clients.created_by only relaxes a constraint.)
--
-- OpenID Connect Dynamic Client Registration (RFC 7591) and client
-- configuration management (RFC 7592).
--
-- * oauth2_registration_settings: one row per tenant. `policy` gates the
--   registration endpoint (off, token_required, open); `default_access` says
--   whether a newly registered client is available to every user or to no one
--   until an admin assigns groups. A missing row means off / none.
-- * oauth2_initial_access_tokens: admin-issued bearer tokens that authorize a
--   registration when the policy is token_required. Hash only (SHA-256 hex of
--   a high-entropy random value), so the plaintext is shown once. Revocable,
--   optional expiry.
-- * oauth2_clients gains the registration bookkeeping: a dynamically
--   registered flag, the Argon2 hash of the client's registration access
--   token (RFC 7592), the initial access token that registered it, the
--   display metadata the consent page shows (logo, client, policy and terms
--   URIs), and the remaining accepted metadata as JSON so the client
--   configuration endpoint can echo it back.
-- * oauth2_clients.created_by becomes nullable: a self-registered client has no
--   creating user. (Its foreign key is already ON DELETE SET NULL, which could
--   never succeed against a NOT NULL column.)
--
-- RLS is the strict tenant-isolation form (NULLIF). The registration endpoint
-- always knows the tenant from the request host, so no unscoped lookup exists.

SET LOCAL ROLE appowner;

CREATE TABLE public.oauth2_registration_settings (
    tenant_id uuid NOT NULL,
    policy varchar(50) DEFAULT 'off' NOT NULL,
    default_access varchar(50) DEFAULT 'none' NOT NULL,
    updated_by uuid,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth2_registration_settings_pkey PRIMARY KEY (tenant_id),
    CONSTRAINT oauth2_registration_settings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_registration_settings_updated_by_fkey FOREIGN KEY (updated_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (updated_by),
    CONSTRAINT chk_oauth2_registration_settings_policy CHECK ((policy IN ('off', 'token_required', 'open'))),
    CONSTRAINT chk_oauth2_registration_settings_default_access CHECK ((default_access IN ('none', 'all')))
);

ALTER TABLE public.oauth2_registration_settings OWNER TO appowner;

ALTER TABLE public.oauth2_registration_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_registration_settings_tenant_isolation ON public.oauth2_registration_settings
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_registration_settings TO appuser;

CREATE TABLE public.oauth2_initial_access_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name varchar(255) NOT NULL,
    token_hash varchar(64) NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    CONSTRAINT oauth2_initial_access_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT oauth2_initial_access_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT oauth2_initial_access_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_initial_access_tokens_created_by_fkey FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by)
);

ALTER TABLE public.oauth2_initial_access_tokens OWNER TO appowner;

CREATE INDEX idx_oauth2_initial_access_tokens_tenant
    ON public.oauth2_initial_access_tokens USING btree (tenant_id, created_at);

ALTER TABLE public.oauth2_initial_access_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_initial_access_tokens_tenant_isolation ON public.oauth2_initial_access_tokens
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_initial_access_tokens TO appuser;

ALTER TABLE public.oauth2_clients
    ALTER COLUMN created_by DROP NOT NULL;

ALTER TABLE public.oauth2_clients
    ADD COLUMN dynamically_registered boolean DEFAULT false NOT NULL,
    ADD COLUMN registration_access_token_hash text,
    ADD COLUMN registered_with_token_id uuid,
    ADD COLUMN logo_uri varchar(2048),
    ADD COLUMN client_uri varchar(2048),
    ADD COLUMN policy_uri varchar(2048),
    ADD COLUMN tos_uri varchar(2048),
    ADD COLUMN registration_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    ADD CONSTRAINT chk_oauth2_clients_registration_access_token_hash_length
        CHECK (((registration_access_token_hash IS NULL) OR (length(registration_access_token_hash) <= 512))),
    ADD CONSTRAINT chk_oauth2_clients_registration_metadata_size
        CHECK ((pg_column_size(registration_metadata) <= 65536)),
    ADD CONSTRAINT oauth2_clients_registered_with_token_id_fkey
        FOREIGN KEY (registered_with_token_id) REFERENCES public.oauth2_initial_access_tokens(id) ON DELETE SET NULL;

-- The creator foreign key spans (created_by, tenant_id), so a bare
-- ON DELETE SET NULL would also null tenant_id and fail; null only created_by.
ALTER TABLE public.oauth2_clients
    DROP CONSTRAINT fk_created_by_user;
ALTER TABLE public.oauth2_clients
    ADD CONSTRAINT fk_created_by_user FOREIGN KEY (created_by, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE SET NULL (created_by) NOT VALID;
ALTER TABLE public.oauth2_clients
    VALIDATE CONSTRAINT fk_created_by_user;
