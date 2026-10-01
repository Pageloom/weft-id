-- RP-initiated logout to upstream OIDC identity providers.
--
-- When a user who signed in through an upstream OIDC connection signs out of
-- WeftID, WeftID can send the browser on to the provider's end_session
-- endpoint (OpenID Connect RP-Initiated Logout 1.0), so the provider session
-- ends too. Off by default per connection.
--
-- * oidc_idp_connections.end_session_endpoint: read from the provider's
--   discovery document (or entered by hand), like the other endpoints.
-- * oidc_idp_connections.sign_out_at_idp: the per-connection toggle.
-- * oidc_idp_sessions.id_token: the upstream ID token that created the
--   session, sent back as id_token_hint. Deleted with the row when the
--   session ends; bounded so a pathological token cannot bloat the table.

SET LOCAL ROLE appowner;

ALTER TABLE public.oidc_idp_connections
    ADD COLUMN end_session_endpoint text,
    ADD COLUMN sign_out_at_idp boolean DEFAULT false NOT NULL;

ALTER TABLE public.oidc_idp_connections
    ADD CONSTRAINT chk_oidc_connections_end_session_endpoint_length
    CHECK (((end_session_endpoint IS NULL) OR (length(end_session_endpoint) <= 2048)));

ALTER TABLE public.oidc_idp_sessions
    ADD COLUMN id_token text;

ALTER TABLE public.oidc_idp_sessions
    ADD CONSTRAINT chk_oidc_idp_sessions_id_token_length
    CHECK (((id_token IS NULL) OR (length(id_token) <= 16384)));
