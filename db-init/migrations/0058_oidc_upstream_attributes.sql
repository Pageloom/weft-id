-- migration-safety: ignore (new table; no existing rows or concurrent writers)
--
-- OIDC upstream IdP attribute mirror snapshot (Iteration 5).
--
-- Parallel to user_idp_attributes (migration 0033) for the consuming
-- (relying-party) direction of OIDC. One row per (user, idp_id,
-- attribute_key) recording what an upstream OIDC IdP last sent for a user.
-- The service layer ``apply_oidc_idp_attributes`` is the only writer; admin
-- and user edits never touch this table.
--
-- The ``idp_id`` FK points at oidc_idp_connections (not
-- saml_identity_providers), so the OIDC snapshot is cleanly separated from
-- the SAML snapshot and CASCADEs when an OIDC connection is deleted.
--
-- RLS mirrors the strict tenant-isolation policy used by the other OIDC
-- upstream tables (migration 0057): both USING and WITH CHECK require
-- tenant_id to equal the request-scoped app.tenant_id, so an UNSCOPED read
-- or write fails closed.

SET LOCAL ROLE appowner;

CREATE TABLE public.user_oidc_idp_attributes (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    attribute_key character varying(64) NOT NULL,
    value text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_oidc_idp_attributes_pkey PRIMARY KEY (user_id, idp_id, attribute_key),
    CONSTRAINT user_oidc_idp_attributes_user_tenant_fkey
        FOREIGN KEY (user_id, tenant_id)
        REFERENCES public.users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT user_oidc_idp_attributes_idp_fkey
        FOREIGN KEY (idp_id)
        REFERENCES public.oidc_idp_connections(id) ON DELETE CASCADE,
    CONSTRAINT user_oidc_idp_attributes_value_length_check CHECK ((length(value) <= 2000))
);

ALTER TABLE public.user_oidc_idp_attributes OWNER TO appowner;

CREATE INDEX user_oidc_idp_attributes_tenant_user_idx
    ON public.user_oidc_idp_attributes USING btree (tenant_id, user_id);
CREATE INDEX user_oidc_idp_attributes_tenant_idp_idx
    ON public.user_oidc_idp_attributes USING btree (tenant_id, idp_id);

ALTER TABLE public.user_oidc_idp_attributes ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_oidc_idp_attributes_tenant_isolation ON public.user_oidc_idp_attributes
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.user_oidc_idp_attributes TO appuser;
