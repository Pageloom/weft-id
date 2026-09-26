-- migration-safety: ignore (the table is CREATEd in this same migration, so it
-- starts empty and there are no existing rows or concurrent writers for the
-- index builds to block; CONCURRENTLY is unnecessary and cannot run
-- in-transaction.)
--
-- Remembered OAuth2 / OIDC consent.
--
-- One row per (client, user) holding the union of every scope the user has
-- allowed for that client. The authorization endpoint skips the consent page
-- when a grant covers every requested scope, and answers prompt=none with a
-- code instead of consent_required. Allowing widens the row; denying never
-- writes. Users revoke their own grants from User Settings; admins revoke
-- per client. Deleting a client cascades here; deactivating a client or a
-- user deletes the grants explicitly (services layer), so a reactivated app
-- or user starts from a fresh consent.
--
-- Scopes are stored as an array (like oauth2_clients.redirect_uris) rather
-- than as rows, because the unit of consent is the set: coverage is a
-- superset test and the UI shows the set as a whole. Bounded so a runaway
-- client cannot grow a row without limit.
--
-- RLS mirrors the strict tenant-isolation policy of the newer tenant tables
-- (NULLIF form, as oidc_idp_connections): USING and WITH CHECK both require
-- tenant_id to equal the request-scoped app.tenant_id, so an UNSCOPED read
-- returns nothing and an UNSCOPED write is rejected.

SET LOCAL ROLE appowner;

CREATE TABLE public.oauth2_consent_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth2_consent_grants_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oauth2_consent_grant_client_user UNIQUE (client_id, user_id),
    CONSTRAINT oauth2_consent_grants_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oauth2_consent_grants_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth2_clients(id) ON DELETE CASCADE,
    CONSTRAINT fk_oauth2_consent_grant_user FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_oauth2_consent_grants_scopes_count CHECK ((cardinality(scopes) <= 50))
);

ALTER TABLE public.oauth2_consent_grants OWNER TO appowner;

CREATE INDEX idx_oauth2_consent_grants_tenant_user ON public.oauth2_consent_grants USING btree (tenant_id, user_id);
CREATE INDEX idx_oauth2_consent_grants_tenant_client ON public.oauth2_consent_grants USING btree (tenant_id, client_id);

ALTER TABLE public.oauth2_consent_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_consent_grants_tenant_isolation ON public.oauth2_consent_grants
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oauth2_consent_grants TO appuser;
