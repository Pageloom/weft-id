-- migration-safety: ignore (the oauth2_clients columns are nullable or have a
-- constant default, catalog-only changes; the CHECKs added with them read a
-- table of a few rows per tenant, and every existing row passes them because
-- client_auth_method starts 'client_secret'. The new table is CREATEd in this
-- same migration, so it starts empty and its index builds block nothing.)
--
-- private_key_jwt client authentication (RFC 7523, OpenID Connect Core 1.0
-- section 9).
--
-- * oauth2_clients.client_auth_method: how a confidential client authenticates.
--   'client_secret' (client_secret_basic or client_secret_post, as before) or
--   'private_key_jwt' (a JWT signed with one of the client's keys). A public
--   client (is_public) authenticates with neither and keeps 'client_secret';
--   the CHECK stops it being 'private_key_jwt'. A private_key_jwt client keeps
--   a client_secret_hash of a random secret nobody sees, so no secret matches.
-- * jwks / jwks_uri: the client's public keys, inline or by URL, never both;
--   a private_key_jwt client must have one.
-- * token_endpoint_auth_signing_alg: the one algorithm the client's
--   assertions must use, when it registered one (RFC 7591 metadata).
-- * Registered clients kept jwks / jwks_uri in registration_metadata, where
--   nothing read them; they move to the columns.
--
-- * oauth2_client_assertion_jtis: the jti of every accepted client assertion
--   until its exp, so an assertion is accepted once (RFC 7523 section 3,
--   Core section 9). Expired rows are swept on the path that adds rows.
--
-- RLS follows the strict NULLIF tenant-isolation policy of the newer tables.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS client_auth_method text DEFAULT 'client_secret'::text NOT NULL,
    ADD COLUMN IF NOT EXISTS jwks jsonb,
    ADD COLUMN IF NOT EXISTS jwks_uri text,
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_signing_alg text,
    ADD CONSTRAINT chk_oauth2_clients_auth_method
        CHECK ((client_auth_method = ANY (ARRAY['client_secret'::text, 'private_key_jwt'::text]))),
    ADD CONSTRAINT chk_oauth2_clients_jwks_one_source
        CHECK (((jwks IS NULL) OR (jwks_uri IS NULL))),
    ADD CONSTRAINT chk_oauth2_clients_jwks_uri_length
        CHECK (((jwks_uri IS NULL) OR (length(jwks_uri) <= 2048))),
    ADD CONSTRAINT chk_oauth2_clients_auth_signing_alg
        CHECK (((token_endpoint_auth_signing_alg IS NULL)
            OR (token_endpoint_auth_signing_alg = ANY (ARRAY['RS256'::text, 'PS256'::text, 'ES256'::text])))),
    ADD CONSTRAINT chk_oauth2_clients_private_key_jwt
        CHECK (((client_auth_method <> 'private_key_jwt'::text)
            OR ((NOT is_public) AND ((jwks IS NOT NULL) OR (jwks_uri IS NOT NULL)))));

UPDATE public.oauth2_clients
SET jwks = registration_metadata -> 'jwks',
    registration_metadata = registration_metadata - 'jwks'
WHERE registration_metadata ? 'jwks' AND jsonb_typeof(registration_metadata -> 'jwks') = 'object';

UPDATE public.oauth2_clients
SET jwks_uri = registration_metadata ->> 'jwks_uri',
    registration_metadata = registration_metadata - 'jwks_uri'
WHERE registration_metadata ? 'jwks_uri' AND jwks IS NULL
  AND length(registration_metadata ->> 'jwks_uri') <= 2048;

CREATE TABLE public.oauth2_client_assertion_jtis (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    jti text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth2_client_assertion_jtis_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oauth2_client_assertion_jtis UNIQUE (tenant_id, client_id, jti),
    CONSTRAINT oauth2_client_assertion_jtis_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_client_assertion_jtis_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth2_client_assertion_jtis_jti_length CHECK ((length(jti) <= 255))
);

ALTER TABLE public.oauth2_client_assertion_jtis OWNER TO appowner;

CREATE INDEX idx_oauth2_client_assertion_jtis_tenant_expires ON public.oauth2_client_assertion_jtis USING btree (tenant_id, expires_at);

ALTER TABLE public.oauth2_client_assertion_jtis ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_client_assertion_jtis_tenant_isolation ON public.oauth2_client_assertion_jtis
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_client_assertion_jtis TO appuser;
