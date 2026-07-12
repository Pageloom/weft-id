-- migration-safety: ignore (additive nullable lookup columns plus unique
-- indexes on them. CREATE INDEX CONCURRENTLY cannot run inside the migration
-- runner's per-file transaction, and these tables hold only short-lived tokens
-- and authorization codes, so the brief build-time lock is acceptable. Existing
-- rows keep token_lookup / code_lookup NULL: their plaintext is unknown so the
-- digest cannot be backfilled. They fall out of the indexed lookup and expire
-- on their own (codes <=10 min, access <=1 h, refresh <=30 d); no live token is
-- deleted here.)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- Indexed lookup digest for opaque access/refresh tokens and authorization
-- codes.
--
-- Tokens are stored only as Argon2 hashes with no lookup key, so validation
-- could not index: it selected every live token in the tenant and ran Argon2
-- verify in a Python loop until one matched. A garbage bearer therefore forced
-- one Argon2 verification per live token (a pre-auth resource-exhaustion / DoS
-- amplifier on /userinfo and /oauth2/token).
--
-- The fix adds a fast, non-secret SHA-256 digest of the opaque token as an
-- indexed lookup key. Each opaque value already carries 256 bits of `secrets`
-- entropy (see oauth2.generate_opaque_token), so the unkeyed digest is not
-- brute-forceable: validation resolves exactly one row, then runs Argon2 once
-- on that single candidate (so a database dump still cannot be replayed).
--
-- char(64) holds a hex SHA-256 (bounded length, no TEXT length-check needed).
-- The unique index is scoped by tenant_id to match the RLS-scoped query path;
-- multiple NULLs are permitted, so pre-existing rows do not collide.
-- ---------------------------------------------------------------------------

ALTER TABLE public.oauth2_tokens
    ADD COLUMN IF NOT EXISTS token_lookup char(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth2_tokens_lookup
    ON public.oauth2_tokens (tenant_id, token_lookup);

ALTER TABLE public.oauth2_authorization_codes
    ADD COLUMN IF NOT EXISTS code_lookup char(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth2_authorization_codes_lookup
    ON public.oauth2_authorization_codes (tenant_id, code_lookup);
