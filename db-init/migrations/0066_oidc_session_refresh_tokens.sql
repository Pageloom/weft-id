-- migration-safety: ignore (additive nullable columns plus one partial index.
-- CREATE INDEX CONCURRENTLY cannot run inside the migration runner's per-file
-- transaction, and oauth2_tokens holds only short-lived rows (access <=1 h,
-- refresh <=30 d), so the brief build-time lock is acceptable, as in 0062.)
--
-- OpenID Connect Back-Channel Logout 1.0, second part.
--
-- * oauth2_tokens.sid: the WeftID session a refresh token was issued in (the
--   ID token's `sid`). Set only when the token endpoint also issued an ID
--   token; carried onto rotated refresh tokens. Ending that session revokes
--   the session's refresh tokens (BCL 2.7), and with them, by the existing
--   parent_token_id cascade, the access tokens minted from them. Existing
--   rows keep NULL: they are not tied to a session and expire on their own.
-- * oidc_session_clients.issuer: the `iss` of the ID token that created the
--   row. A logout token's `iss` must equal the ID token's, and consumers that
--   have no request (user deactivation by a worker job) cannot derive the
--   tenant host. Rows written before this migration keep NULL; consumers fall
--   back to the tenant's canonical host.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_tokens
    ADD COLUMN IF NOT EXISTS sid varchar(64);

CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_sid
    ON public.oauth2_tokens (tenant_id, sid)
    WHERE sid IS NOT NULL;

ALTER TABLE public.oidc_session_clients
    ADD COLUMN IF NOT EXISTS issuer varchar(2048);

-- User deactivation consumes every row of one user.
CREATE INDEX IF NOT EXISTS idx_oidc_session_clients_user
    ON public.oidc_session_clients (tenant_id, user_id);
