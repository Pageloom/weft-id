-- migration-safety: ignore (the oauth2_clients column has a constant default,
-- a catalog-only change; the CHECK added with it reads a table of a few rows
-- per tenant, and every existing row passes it because the column starts
-- false. The new table is CREATEd in this same migration, so it starts empty
-- and its index builds block nothing.)
--
-- Pushed Authorization Requests (RFC 9126).
--
-- * oauth2_clients.require_pushed_authorization_requests: the client may only
--   start an authorization through the PAR endpoint (RFC 9126 section 6).
--   Only a normal, confidential client can push, so only one can require it.
-- * oauth2_pushed_authorization_requests: a pushed request's parameters,
--   found by the SHA-256 of the reference in its request_uri, bound to the
--   client that pushed it, single use (the row is deleted when redeemed) and
--   short-lived. Expired rows are swept on the path that adds rows.
--
-- RLS follows the strict NULLIF tenant-isolation policy of the newer tables.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN IF NOT EXISTS require_pushed_authorization_requests boolean DEFAULT false NOT NULL,
    ADD CONSTRAINT chk_oauth2_clients_require_par
        CHECK (((NOT require_pushed_authorization_requests)
            OR ((client_type = 'normal'::text) AND (NOT is_public))));

CREATE TABLE public.oauth2_pushed_authorization_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    reference_hash text NOT NULL,
    parameters jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth2_pushed_authorization_requests_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oauth2_pushed_authorization_requests_reference UNIQUE (tenant_id, reference_hash),
    CONSTRAINT oauth2_pushed_authorization_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_pushed_authorization_requests_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth2_pushed_authorization_requests_hash_length CHECK ((length(reference_hash) <= 128)),
    CONSTRAINT chk_oauth2_pushed_authorization_requests_parameters CHECK ((jsonb_typeof(parameters) = 'object'::text))
);

ALTER TABLE public.oauth2_pushed_authorization_requests OWNER TO appowner;

CREATE INDEX idx_oauth2_pushed_authorization_requests_tenant_expires ON public.oauth2_pushed_authorization_requests USING btree (tenant_id, expires_at);
CREATE INDEX idx_oauth2_pushed_authorization_requests_client ON public.oauth2_pushed_authorization_requests USING btree (client_id);

ALTER TABLE public.oauth2_pushed_authorization_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_pushed_authorization_requests_tenant_isolation ON public.oauth2_pushed_authorization_requests
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_pushed_authorization_requests TO appuser;
