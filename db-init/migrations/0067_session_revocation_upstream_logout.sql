-- migration-safety: ignore (all three tables are CREATEd in this same
-- migration, so they start empty and there are no existing rows or concurrent
-- writers for the index builds to block; CONCURRENTLY is unnecessary and
-- cannot run in-transaction.)
--
-- Server-side session revocation and upstream OIDC back-channel logout.
--
-- WeftID sessions are signed cookies with no server-side store. Ending one
-- from the server (an upstream IdP's logout token, or making a local logout
-- stick against a copied cookie) needs a record the request path consults:
--
-- * revoked_sessions: one row per ended WeftID session identifier (the `sid`
--   the session carries, also the OIDC `sid` claim). Every authenticated
--   request checks it; a listed sid is signed out. Starlette re-signs the
--   cookie on every response and refuses one idle longer than its max_age
--   (14 days), so a revoked sid is either presented within that window or its
--   cookie is dead: rows are purged after 15 days.
-- * oidc_idp_sessions: which upstream OIDC sign-in created which WeftID
--   session (connection, upstream `sub`, upstream `sid` when the IdP sends
--   one). A logout token names the upstream session; this maps it to the
--   WeftID sessions to revoke. One row per WeftID session. Deleted when the
--   session is revoked; sessions that ended by cookie expiry are swept after
--   90 days (the same horizon as oidc_session_clients).
-- * oidc_idp_logout_token_jtis: the `jti` of every accepted logout token,
--   kept until the token expires, so a replayed token is refused.
--
-- RLS is the strict tenant-isolation form (NULLIF). The worker's cross-tenant
-- retention goes through SECURITY DEFINER functions (the 0065 pattern).

SET LOCAL ROLE appowner;

CREATE TABLE public.revoked_sessions (
    tenant_id uuid NOT NULL,
    sid varchar(64) NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT revoked_sessions_pkey PRIMARY KEY (tenant_id, sid),
    CONSTRAINT revoked_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE
);

ALTER TABLE public.revoked_sessions OWNER TO appowner;

CREATE INDEX idx_revoked_sessions_revoked_at
    ON public.revoked_sessions USING btree (revoked_at);

ALTER TABLE public.revoked_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY revoked_sessions_tenant_isolation ON public.revoked_sessions
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.revoked_sessions TO appuser;

CREATE TABLE public.oidc_idp_sessions (
    tenant_id uuid NOT NULL,
    sid varchar(64) NOT NULL,
    idp_id uuid NOT NULL,
    user_id uuid NOT NULL,
    upstream_sub text NOT NULL,
    upstream_sid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_idp_sessions_pkey PRIMARY KEY (tenant_id, sid),
    CONSTRAINT oidc_idp_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oidc_idp_sessions_idp_id_fkey FOREIGN KEY (idp_id) REFERENCES public.oidc_idp_connections(id) ON DELETE CASCADE,
    CONSTRAINT fk_oidc_idp_sessions_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_oidc_idp_sessions_upstream_sub_length CHECK ((length(upstream_sub) <= 255)),
    CONSTRAINT chk_oidc_idp_sessions_upstream_sid_length CHECK (((upstream_sid IS NULL) OR (length(upstream_sid) <= 255)))
);

ALTER TABLE public.oidc_idp_sessions OWNER TO appowner;

CREATE INDEX idx_oidc_idp_sessions_upstream_sid
    ON public.oidc_idp_sessions USING btree (idp_id, upstream_sid)
    WHERE upstream_sid IS NOT NULL;
CREATE INDEX idx_oidc_idp_sessions_upstream_sub
    ON public.oidc_idp_sessions USING btree (idp_id, upstream_sub);
CREATE INDEX idx_oidc_idp_sessions_created_at
    ON public.oidc_idp_sessions USING btree (created_at);

ALTER TABLE public.oidc_idp_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_idp_sessions_tenant_isolation ON public.oidc_idp_sessions
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_idp_sessions TO appuser;

CREATE TABLE public.oidc_idp_logout_token_jtis (
    tenant_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    jti text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_idp_logout_token_jtis_pkey PRIMARY KEY (tenant_id, idp_id, jti),
    CONSTRAINT oidc_idp_logout_token_jtis_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oidc_idp_logout_token_jtis_idp_id_fkey FOREIGN KEY (idp_id) REFERENCES public.oidc_idp_connections(id) ON DELETE CASCADE,
    CONSTRAINT chk_oidc_idp_logout_token_jtis_jti_length CHECK ((length(jti) <= 255))
);

ALTER TABLE public.oidc_idp_logout_token_jtis OWNER TO appowner;

CREATE INDEX idx_oidc_idp_logout_token_jtis_expires_at
    ON public.oidc_idp_logout_token_jtis USING btree (expires_at);

ALTER TABLE public.oidc_idp_logout_token_jtis ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_idp_logout_token_jtis_tenant_isolation ON public.oidc_idp_logout_token_jtis
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_idp_logout_token_jtis TO appuser;

-- SECURITY DEFINER retention functions: owned by appowner (exempt from RLS
-- because FORCE ROW LEVEL SECURITY is not set). search_path is pinned and
-- table names are fully qualified.

CREATE OR REPLACE FUNCTION public.purge_revoked_sessions(p_older_than interval)
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    WITH purged AS (
        DELETE FROM public.revoked_sessions r
        WHERE r.revoked_at < now() - p_older_than
        RETURNING 1
    )
    SELECT count(*)::integer FROM purged
$$;

CREATE OR REPLACE FUNCTION public.sweep_stale_oidc_idp_sessions(p_older_than interval)
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    WITH swept AS (
        DELETE FROM public.oidc_idp_sessions s
        WHERE s.created_at < now() - p_older_than
        RETURNING 1
    )
    SELECT count(*)::integer FROM swept
$$;

CREATE OR REPLACE FUNCTION public.purge_expired_oidc_idp_logout_token_jtis()
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    WITH purged AS (
        DELETE FROM public.oidc_idp_logout_token_jtis j
        WHERE j.expires_at < now()
        RETURNING 1
    )
    SELECT count(*)::integer FROM purged
$$;

REVOKE ALL ON FUNCTION public.purge_revoked_sessions(interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sweep_stale_oidc_idp_sessions(interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.purge_expired_oidc_idp_logout_token_jtis() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.purge_revoked_sessions(interval) TO appuser;
GRANT EXECUTE ON FUNCTION public.sweep_stale_oidc_idp_sessions(interval) TO appuser;
GRANT EXECUTE ON FUNCTION public.purge_expired_oidc_idp_logout_token_jtis() TO appuser;
