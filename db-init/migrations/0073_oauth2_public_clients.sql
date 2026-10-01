-- migration-safety: ignore (adds a column with a constant default, a
-- catalog-only change; the CHECK added with it reads a table of a few rows per
-- tenant, and every existing row passes it because is_public starts false.)
--
-- Public OAuth 2.0 clients (RFC 6749 section 2.1) for the device
-- authorization grant.
--
-- * oauth2_clients.is_public: the client has no secret and identifies itself by
--   client_id alone (token_endpoint_auth_method "none"). Chosen at creation and
--   never changed. client_secret_hash stays NOT NULL: a public client stores the
--   hash of a random secret nobody ever sees, and the authentication code never
--   compares a secret for a public client.
--
-- The CHECK keeps a public client to what it may do: a normal client with the
-- device grant on (it may use device_code and refresh_token only; the token
-- endpoint enforces the grant list).

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS is_public boolean DEFAULT false NOT NULL,
    ADD CONSTRAINT chk_oauth2_clients_public_device_only
        CHECK ((NOT is_public) OR ((client_type = 'normal'::text) AND device_grant_enabled));
