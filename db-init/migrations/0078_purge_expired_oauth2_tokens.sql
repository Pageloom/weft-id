-- Retention sweep for expired OAuth2 access and refresh tokens.
--
-- Validation already ignores a token past expires_at, so these rows are dead
-- weight; nothing deleted them. The worker's daily OIDC cleanup calls this
-- function. It is cross-tenant, and oauth2_tokens has the strict RLS policy,
-- so it is a SECURITY DEFINER function owned by appowner (exempt from RLS
-- because FORCE ROW LEVEL SECURITY is not set), like the 0067 sweeps.
--
-- The grace period keeps a refresh token until well after any access token
-- minted from it has expired too: access tokens live at most an hour, and the
-- parent_token_id foreign key cascades.

SET LOCAL ROLE appowner;

CREATE OR REPLACE FUNCTION public.purge_expired_oauth2_tokens(p_older_than interval)
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    WITH purged AS (
        DELETE FROM public.oauth2_tokens t
        WHERE t.expires_at < now() - p_older_than
        RETURNING 1
    )
    SELECT count(*)::integer FROM purged
$$;

REVOKE ALL ON FUNCTION public.purge_expired_oauth2_tokens(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.purge_expired_oauth2_tokens(interval) TO appuser;
