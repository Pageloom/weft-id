-- OpenID Connect third-party-initiated login (Core 1.0 section 4).
--
-- * oauth2_clients.initiate_login_uri: the RP URL that starts a login at
--   WeftID. Set by an admin on any normal client, or by the client itself at
--   dynamic registration. When set on an OIDC-enabled client, the app appears
--   in My Apps and launches by navigating here with `iss`. https only (checked
--   in the service layer). A nullable column with no default is a catalog-only
--   change.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS initiate_login_uri varchar(2048);
