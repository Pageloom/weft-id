-- migration-safety: ignore (both tables are CREATEd in this same migration, so
-- they start empty and there are no existing rows or concurrent writers for the
-- index builds to block; CONCURRENTLY is unnecessary and cannot run in-transaction.)
--
-- OIDC upstream IdP connections (Iteration 1: data model).
--
-- WeftID consumes OIDC IdPs (the relying-party direction) as a peer to the
-- existing SAML IdP support. This migration creates the two tables the
-- connector needs now, with the full column set settled up front so no later
-- iteration needs a second migration on the same table:
--
--   * oidc_idp_connections -- one row per upstream OIDC connection, mirroring
--     saml_identity_providers (name, provider_type CHECK, claim mapping,
--     enable/default/MFA/JIT flags, provenance) plus OIDC-specific endpoint
--     and credential columns. The client secret is stored encrypted at rest
--     (reversible) because it authenticates outbound requests to the IdP.
--
--   * oidc_idp_user_links -- maps (tenant_id, idp_id, sub) to a WeftID user,
--     UNIQUE (idp_id, sub). OIDC correlates users on the stable `sub` claim
--     (or a per-connection correlation_claim such as Entra's `oid`), unlike
--     SAML's email correlation. Written by the auth flow (Iteration 3); this
--     iteration only creates the table and tests it at the database layer.
--
-- RLS mirrors the strict tenant-isolation policy used by
-- saml_identity_providers: both USING and WITH CHECK require tenant_id to
-- equal the request-scoped app.tenant_id, so an UNSCOPED read or write fails
-- closed.
--
-- The single-default trigger mirrors ensure_single_default_idp so only one
-- OIDC connection per tenant can be is_default at a time.

SET LOCAL ROLE appowner;

CREATE TABLE public.oidc_idp_connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    provider_type text NOT NULL,
    issuer text NOT NULL,
    discovery_url text,
    authorization_endpoint text,
    token_endpoint text,
    userinfo_endpoint text,
    jwks_uri text,
    discovery_fetched_at timestamp with time zone,
    discovery_error text,
    client_id text,
    client_secret_enc text,
    scopes text,
    claim_mapping jsonb DEFAULT '{"email": "email", "first_name": "given_name", "last_name": "family_name"}'::jsonb NOT NULL,
    correlation_claim text DEFAULT 'sub'::text NOT NULL,
    group_claim_source text,
    hosted_domain text,
    entra_tenant_id text,
    is_enabled boolean DEFAULT false NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    require_platform_mfa boolean DEFAULT false NOT NULL,
    jit_provisioning boolean DEFAULT false NOT NULL,
    allow_email_linking boolean DEFAULT false NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_idp_connections_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oidc_connection_tenant_name UNIQUE (tenant_id, name),
    CONSTRAINT oidc_idp_connections_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_oidc_connection_created_by_user FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL,
    CONSTRAINT oidc_idp_connections_provider_type_check CHECK ((provider_type = ANY (ARRAY['generic'::text, 'google'::text, 'entra'::text]))),
    CONSTRAINT chk_oidc_connection_name_length CHECK ((length(name) <= 120)),
    CONSTRAINT chk_oidc_connection_issuer_length CHECK ((length(issuer) <= 2048)),
    CONSTRAINT chk_oidc_connection_discovery_url_length CHECK (((discovery_url IS NULL) OR (length(discovery_url) <= 2048))),
    CONSTRAINT chk_oidc_connection_authorization_endpoint_length CHECK (((authorization_endpoint IS NULL) OR (length(authorization_endpoint) <= 2048))),
    CONSTRAINT chk_oidc_connection_token_endpoint_length CHECK (((token_endpoint IS NULL) OR (length(token_endpoint) <= 2048))),
    CONSTRAINT chk_oidc_connection_userinfo_endpoint_length CHECK (((userinfo_endpoint IS NULL) OR (length(userinfo_endpoint) <= 2048))),
    CONSTRAINT chk_oidc_connection_jwks_uri_length CHECK (((jwks_uri IS NULL) OR (length(jwks_uri) <= 2048))),
    CONSTRAINT chk_oidc_connection_discovery_error_length CHECK (((discovery_error IS NULL) OR (length(discovery_error) <= 10000))),
    CONSTRAINT chk_oidc_connection_client_id_length CHECK (((client_id IS NULL) OR (length(client_id) <= 255))),
    CONSTRAINT chk_oidc_connection_client_secret_enc_length CHECK (((client_secret_enc IS NULL) OR (length(client_secret_enc) <= 4096))),
    CONSTRAINT chk_oidc_connection_scopes_length CHECK (((scopes IS NULL) OR (length(scopes) <= 500))),
    CONSTRAINT chk_oidc_connection_correlation_claim_length CHECK ((length(correlation_claim) <= 50)),
    CONSTRAINT chk_oidc_connection_group_claim_source_length CHECK (((group_claim_source IS NULL) OR (length(group_claim_source) <= 255))),
    CONSTRAINT chk_oidc_connection_hosted_domain_length CHECK (((hosted_domain IS NULL) OR (length(hosted_domain) <= 253))),
    CONSTRAINT chk_oidc_connection_entra_tenant_id_length CHECK (((entra_tenant_id IS NULL) OR (length(entra_tenant_id) <= 100)))
);

ALTER TABLE public.oidc_idp_connections OWNER TO appowner;

CREATE TABLE public.oidc_idp_user_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    sub text NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_idp_user_links_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oidc_user_link_idp_sub UNIQUE (idp_id, sub),
    CONSTRAINT oidc_idp_user_links_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oidc_idp_user_links_idp_id_fkey FOREIGN KEY (idp_id) REFERENCES public.oidc_idp_connections(id) ON DELETE CASCADE,
    CONSTRAINT oidc_idp_user_links_user_tenant_fkey FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_oidc_user_link_sub_length CHECK ((length(sub) <= 255))
);

ALTER TABLE public.oidc_idp_user_links OWNER TO appowner;

CREATE INDEX idx_oidc_connections_tenant ON public.oidc_idp_connections USING btree (tenant_id);
CREATE INDEX idx_oidc_connections_tenant_default ON public.oidc_idp_connections USING btree (tenant_id) WHERE (is_default = true);
CREATE INDEX idx_oidc_connections_tenant_enabled ON public.oidc_idp_connections USING btree (tenant_id) WHERE (is_enabled = true);
CREATE INDEX idx_oidc_user_links_tenant ON public.oidc_idp_user_links USING btree (tenant_id);
CREATE INDEX idx_oidc_user_links_idp ON public.oidc_idp_user_links USING btree (idp_id);
CREATE INDEX idx_oidc_user_links_user ON public.oidc_idp_user_links USING btree (user_id);

CREATE FUNCTION public.ensure_single_default_oidc_connection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_default = true THEN
        UPDATE oidc_idp_connections
        SET is_default = false, updated_at = now()
        WHERE tenant_id = NEW.tenant_id
          AND id != NEW.id
          AND is_default = true;
    END IF;
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.ensure_single_default_oidc_connection() OWNER TO appowner;

CREATE FUNCTION public.update_oidc_connection_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.update_oidc_connection_updated_at() OWNER TO appowner;

CREATE TRIGGER trg_ensure_single_default_oidc_connection
    BEFORE INSERT OR UPDATE OF is_default ON public.oidc_idp_connections
    FOR EACH ROW WHEN ((new.is_default = true))
    EXECUTE FUNCTION public.ensure_single_default_oidc_connection();

CREATE TRIGGER trg_oidc_connection_updated_at
    BEFORE UPDATE ON public.oidc_idp_connections
    FOR EACH ROW
    EXECUTE FUNCTION public.update_oidc_connection_updated_at();

ALTER TABLE public.oidc_idp_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_connections_tenant_isolation ON public.oidc_idp_connections
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

ALTER TABLE public.oidc_idp_user_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_user_links_tenant_isolation ON public.oidc_idp_user_links
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_idp_connections TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_idp_user_links TO appuser;
