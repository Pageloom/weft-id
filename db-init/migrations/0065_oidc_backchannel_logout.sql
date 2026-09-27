-- migration-safety: ignore (oidc_backchannel_logout_deliveries is CREATEd in
-- this same migration, so it starts empty and there are no existing rows or
-- concurrent writers for the index builds to block; CONCURRENTLY is
-- unnecessary and cannot run in-transaction.)
--
-- OpenID Connect Back-Channel Logout 1.0.
--
-- * oauth2_clients.backchannel_logout_uri: the RP URL WeftID POSTs a signed
--   logout token to when the user's WeftID session ends. NULL means the
--   client does not take part in back-channel logout.
-- * oauth2_clients.backchannel_logout_session_required: when true, the logout
--   token carries the `sid` claim. Defaults to true, like the front-channel
--   flag (the spec's default is false); `sub` is always sent.
-- * oidc_backchannel_logout_deliveries: one row per (ended session, client),
--   written in the same statement that consumes the session's
--   oidc_session_clients rows. It is the worker's queue (status 'pending',
--   next_attempt_at) and the delivery log ('delivered' / 'failed', attempts,
--   last error). `sub` is not a foreign key: a delivery for a deleted user
--   must still go out. `issuer` is captured at enqueue, because the logout
--   token's `iss` must equal the ID token's and the worker has no request to
--   derive the tenant host from.
--
-- RLS is the strict form (NULLIF). The worker's cross-tenant needs go through
-- SECURITY DEFINER functions (the 0040 pattern) instead of a widened policy:
-- * list_tenants_with_due_backchannel_logouts(): which tenants have work;
-- * purge_backchannel_logout_deliveries(interval): finished rows retention;
-- * sweep_stale_oidc_session_clients(interval): session rows of sessions that
--   ended without a logout (expired cookies) and so were never consumed.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS backchannel_logout_uri varchar(2048);

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS backchannel_logout_session_required boolean NOT NULL DEFAULT true;

CREATE TABLE public.oidc_backchannel_logout_deliveries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    sub varchar(64) NOT NULL,
    sid varchar(64),
    issuer varchar(2048) NOT NULL,
    status varchar(20) DEFAULT 'pending' NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_attempt_at timestamp with time zone,
    last_http_status integer,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT oidc_backchannel_logout_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_backchannel_logout_deliveries_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oidc_backchannel_logout_deliveries_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT chk_oidc_backchannel_logout_deliveries_status
        CHECK (status IN ('pending', 'delivered', 'failed')),
    CONSTRAINT chk_oidc_backchannel_logout_deliveries_last_error_length
        CHECK (last_error IS NULL OR length(last_error) <= 1000)
);

ALTER TABLE public.oidc_backchannel_logout_deliveries OWNER TO appowner;

CREATE INDEX idx_oidc_backchannel_logout_deliveries_due
    ON public.oidc_backchannel_logout_deliveries USING btree (next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX idx_oidc_backchannel_logout_deliveries_client
    ON public.oidc_backchannel_logout_deliveries USING btree (client_id, created_at);
CREATE INDEX idx_oidc_backchannel_logout_deliveries_completed
    ON public.oidc_backchannel_logout_deliveries USING btree (completed_at)
    WHERE status <> 'pending';

ALTER TABLE public.oidc_backchannel_logout_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_backchannel_logout_deliveries_tenant_isolation
    ON public.oidc_backchannel_logout_deliveries
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_backchannel_logout_deliveries TO appuser;

-- The sweep below filters on last_issued_at across all tenants.
CREATE INDEX idx_oidc_session_clients_last_issued
    ON public.oidc_session_clients USING btree (last_issued_at);

-- SECURITY DEFINER functions: owned by appowner (the table owner, exempt from
-- RLS because FORCE ROW LEVEL SECURITY is not set). search_path is pinned and
-- table names are fully qualified (standard SECURITY DEFINER hardening).

CREATE OR REPLACE FUNCTION public.list_tenants_with_due_backchannel_logouts()
RETURNS TABLE (tenant_id uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    SELECT DISTINCT d.tenant_id
    FROM public.oidc_backchannel_logout_deliveries d
    WHERE d.status = 'pending' AND d.next_attempt_at <= now()
$$;

CREATE OR REPLACE FUNCTION public.purge_backchannel_logout_deliveries(p_older_than interval)
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    WITH purged AS (
        DELETE FROM public.oidc_backchannel_logout_deliveries d
        WHERE d.status <> 'pending' AND d.completed_at < now() - p_older_than
        RETURNING 1
    )
    SELECT count(*)::integer FROM purged
$$;

CREATE OR REPLACE FUNCTION public.sweep_stale_oidc_session_clients(p_older_than interval)
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
    WITH swept AS (
        DELETE FROM public.oidc_session_clients s
        WHERE s.last_issued_at < now() - p_older_than
        RETURNING 1
    )
    SELECT count(*)::integer FROM swept
$$;

REVOKE ALL ON FUNCTION public.list_tenants_with_due_backchannel_logouts() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.purge_backchannel_logout_deliveries(interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sweep_stale_oidc_session_clients(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.list_tenants_with_due_backchannel_logouts() TO appuser;
GRANT EXECUTE ON FUNCTION public.purge_backchannel_logout_deliveries(interval) TO appuser;
GRANT EXECUTE ON FUNCTION public.sweep_stale_oidc_session_clients(interval) TO appuser;
