-- migration-safety: ignore (additive nullable columns plus one partial index.
-- CREATE INDEX CONCURRENTLY cannot run inside the migration runner's per-file
-- transaction, and oauth2_tokens holds only short-lived rows (access <=1 h,
-- refresh <=30 d), so the brief build-time lock is acceptable. Existing rows
-- keep grant_id NULL: they predate code-reuse revocation and expire on their
-- own.)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- Authorization-code reuse detection (RFC 6749 section 4.1.2, OAuth 2.0
-- Security BCP section 4.5).
--
-- A redeemed authorization code used to be deleted, so a second redemption
-- was indistinguishable from an unknown code. The spec says the second
-- attempt SHOULD revoke every token already issued from that code, because
-- the code has evidently leaked.
--
-- * oauth2_authorization_codes.consumed_at marks a redeemed code instead of
--   deleting it. It stays until it expires (codes live 5 minutes) and the
--   cleanup job removes it with the other expired codes.
-- * oauth2_tokens.grant_id ties every token to the authorization code that
--   started its grant (the code's id). It is carried onto rotated refresh
--   tokens and onto access tokens minted by the refresh grant, so revoking a
--   grant reaches every descendant. Not a foreign key: the code row is
--   deleted by cleanup long before its tokens expire.
-- ---------------------------------------------------------------------------

ALTER TABLE public.oauth2_authorization_codes
    ADD COLUMN IF NOT EXISTS consumed_at timestamptz;

ALTER TABLE public.oauth2_tokens
    ADD COLUMN IF NOT EXISTS grant_id uuid;

CREATE INDEX IF NOT EXISTS idx_oauth2_tokens_grant
    ON public.oauth2_tokens (tenant_id, grant_id)
    WHERE grant_id IS NOT NULL;
