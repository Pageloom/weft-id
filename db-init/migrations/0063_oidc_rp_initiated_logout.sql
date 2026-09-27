SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- OpenID Connect RP-Initiated Logout 1.0 and the `sid` claim.
--
-- * oauth2_clients.post_logout_redirect_uris: the exact URIs a relying party
--   may ask the end_session endpoint to send the browser back to after
--   logout. Separate from redirect_uris (a different registration, per the
--   spec). Empty means the RP can end the session but is never redirected.
-- * oauth2_authorization_codes.sid: the WeftID session identifier the code
--   was issued in, carried into the ID token's `sid` claim so logout
--   mechanisms can name the session. Random, opaque, minted per login.
-- ---------------------------------------------------------------------------

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';

ALTER TABLE public.oauth2_clients
    ADD CONSTRAINT chk_oauth2_clients_post_logout_redirect_uris_count
    CHECK ((cardinality(post_logout_redirect_uris) <= 50));

ALTER TABLE public.oauth2_authorization_codes
    ADD COLUMN IF NOT EXISTS sid varchar(64);
