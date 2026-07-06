-- OIDC ID-token issuance support.
--
-- WeftID acts as a downstream OIDC provider. Iteration 1 shipped the per-tenant
-- signing key + JWKS. This iteration adds the columns needed to issue signed
-- RS256 ID tokens from the existing OAuth2 authorization-code flow:
--
--   * oauth2_clients.oidc_enabled  -- opt-in flag. Only clients with this set
--     (AND an `openid` scope on the request) get an id_token. Existing
--     plain-OAuth2 clients default to false and are completely unaffected.
--   * oauth2_authorization_codes.scope / nonce / auth_time -- the OIDC request
--     parameters, captured at authorize time and carried onto the code so the
--     token endpoint can mint claims and echo the nonce. auth_time records the
--     user's authentication time (session login timestamp, else code issuance).
--   * oauth2_tokens.scope -- the granted scopes, persisted so later iterations
--     (userinfo) can gate released claims by the access token's scopes.
--
-- All new columns are nullable or DEFAULT-backed, so the migration is safe to
-- apply on a running instance and existing rows keep working unchanged.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS oidc_enabled boolean DEFAULT false NOT NULL;

ALTER TABLE public.oauth2_authorization_codes
    ADD COLUMN IF NOT EXISTS scope character varying(500),
    ADD COLUMN IF NOT EXISTS nonce character varying(512),
    ADD COLUMN IF NOT EXISTS auth_time timestamp with time zone;

ALTER TABLE public.oauth2_authorization_codes
    ADD CONSTRAINT chk_oauth2_codes_scope_length
        CHECK (((scope IS NULL) OR (length(scope) <= 500))),
    ADD CONSTRAINT chk_oauth2_codes_nonce_length
        CHECK (((nonce IS NULL) OR (length(nonce) <= 512)));

ALTER TABLE public.oauth2_tokens
    ADD COLUMN IF NOT EXISTS scope character varying(500);

ALTER TABLE public.oauth2_tokens
    ADD CONSTRAINT chk_oauth2_tokens_scope_length
        CHECK (((scope IS NULL) OR (length(scope) <= 500)));
