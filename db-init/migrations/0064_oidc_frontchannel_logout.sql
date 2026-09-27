-- migration-safety: ignore (oidc_session_clients is CREATEd in this same
-- migration, so it starts empty and there are no existing rows or concurrent
-- writers for the index build to block; CONCURRENTLY is unnecessary and
-- cannot run in-transaction.)
--
-- OpenID Connect Front-Channel Logout 1.0.
--
-- * oauth2_clients.frontchannel_logout_uri: the RP URL the OP loads in an
--   iframe when the user's WeftID session ends. NULL means the client does
--   not take part in front-channel logout.
-- * oauth2_clients.frontchannel_logout_session_required: when true, the
--   iframe URL carries the `iss` and `sid` query parameters. Defaults to
--   true (the spec's default is false): browsers that block third-party
--   cookies hide the RP's own session cookie from the iframe, so most RPs
--   can only find the session to end through `sid`.
-- * oidc_session_clients: which clients received an ID token in which WeftID
--   session (the `sid` claim), so ending the session can notify exactly
--   those RPs. Written at the token endpoint, consumed (deleted) when the
--   session ends. Back-channel logout reads the same rows. Deleting a client
--   or user cascades here.
--
-- RLS is the strict tenant-isolation form (NULLIF, as oauth2_consent_grants):
-- UNSCOPED reads return nothing and UNSCOPED writes are rejected.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS frontchannel_logout_uri varchar(2048);

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS frontchannel_logout_session_required boolean NOT NULL DEFAULT true;

CREATE TABLE public.oidc_session_clients (
    tenant_id uuid NOT NULL,
    sid varchar(64) NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_issued_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_session_clients_pkey PRIMARY KEY (tenant_id, sid, client_id),
    CONSTRAINT oidc_session_clients_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oidc_session_clients_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_oidc_session_clients_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE
);

ALTER TABLE public.oidc_session_clients OWNER TO appowner;

CREATE INDEX idx_oidc_session_clients_client ON public.oidc_session_clients USING btree (client_id);

ALTER TABLE public.oidc_session_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_session_clients_tenant_isolation ON public.oidc_session_clients
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_session_clients TO appuser;
