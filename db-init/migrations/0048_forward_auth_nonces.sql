-- migration-safety: ignore (the table is CREATEd in this same migration, so its
-- index acquires a lock only on an empty, not-yet-referenced table -- no live
-- writes to block; CONCURRENTLY is unnecessary and cannot run in-transaction.)
-- forward_auth_nonces: single-use authorization-token nonces
--
-- The forward-auth handshake mints a short-lived, single-use authorization
-- token (the redirect token from /forward-auth/authorize to
-- /forward-auth/callback). To make the token single-use, its nonce is recorded
-- here at mint time and atomically CONSUMED (deleted) at redemption. A second
-- redemption of the same token finds no row and is rejected as a replay.
--
-- Scoped tenant + domain: a nonce is bound to the tenant that minted it and the
-- protected domain the token authorizes, matching the token's own binding.
--
-- expires_at lets a cleanup path (jobs, iteration 5) purge stale rows. Rows are
-- normally removed on consume; expired-but-unconsumed rows linger until cleaned.
--
-- RLS: the redeem (consume) path runs on the portal host PRE-AUTH -- before any
-- tenant scope is established (the /callback request has no central session).
-- It therefore consumes the nonce with database.UNSCOPED, mirroring the
-- protected_domains 0047 / scim_inbound_tokens 0045 precedent: when
-- app.tenant_id is unset/empty all rows are visible, when set only the scoped
-- tenant's rows are visible. The nonce value is a 256-bit random secret
-- (secrets.token_hex(32)) and unique, so an UNSCOPED consume cannot guess or
-- collide across tenants, and the token's HMAC separately binds {tenant,
-- domain, ...} so a consumed nonce alone grants nothing. The mint (insert) path
-- runs on the canonical tenant host WITH a known tenant scope, so it is
-- tenant-scoped (WITH CHECK enforces the row's tenant_id matches).

SET LOCAL ROLE appowner;

CREATE TABLE forward_auth_nonces (
    -- The nonce itself: a 256-bit random hex secret, globally unique.
    nonce VARCHAR(128) PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The protected domain the authorizing token is bound to.
    domain VARCHAR(253) NOT NULL,
    -- When this nonce (and its token) expires; basis for cleanup.
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_forward_auth_nonces_nonce_length
        CHECK (length(nonce) <= 128),
    CONSTRAINT chk_forward_auth_nonces_domain_length
        CHECK (length(domain) <= 253)
);

-- Cleanup scans by expiry.
CREATE INDEX idx_forward_auth_nonces_expires_at
    ON forward_auth_nonces (expires_at);

ALTER TABLE forward_auth_nonces ENABLE ROW LEVEL SECURITY;

-- Mirrors 0047: UNSCOPED (unset app.tenant_id) sees all rows so the pre-auth
-- /callback consume can find the nonce before a tenant scope exists; a set
-- scope isolates to that tenant. Writes from the mint path run scoped, so the
-- WITH CHECK enforces tenant ownership on INSERT.
CREATE POLICY forward_auth_nonces_tenant_isolation
    ON forward_auth_nonces
    FOR ALL
    TO appuser
    USING (
        CASE
            WHEN (NULLIF(current_setting('app.tenant_id', true), '') IS NULL) THEN true
            ELSE (tenant_id = current_setting('app.tenant_id', true)::uuid)
        END)
    WITH CHECK (
        CASE
            WHEN (NULLIF(current_setting('app.tenant_id', true), '') IS NULL) THEN true
            ELSE (tenant_id = current_setting('app.tenant_id', true)::uuid)
        END);

GRANT SELECT, INSERT, UPDATE, DELETE ON forward_auth_nonces TO appuser;
