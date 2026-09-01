-- migration-safety: ignore (new table; no existing rows or concurrent writers)
--
-- OIDC upstream IdP domain bindings (Iteration 6: privileged domain routing).
--
-- Parallel to saml_idp_domain_bindings for the consuming (relying-party)
-- direction of OIDC. Maps a tenant_privileged_domains row to an OIDC
-- connection so the email-first login flow can route unknown users to the
-- connection's JIT flow.
--
-- A domain binds to at most one IdP across BOTH protocols. The UNIQUE
-- (tenant_id, domain_id) constraint only spans this table, so the
-- cross-protocol exclusivity (a domain cannot be bound to a SAML IdP and an
-- OIDC connection simultaneously) is enforced in the service layer, which
-- checks the other protocol's binding table before inserting.
--
-- RLS mirrors the strict tenant-isolation policy used by the other OIDC
-- upstream tables (migration 0057): both USING and WITH CHECK require
-- tenant_id to equal the request-scoped app.tenant_id, so an UNSCOPED read
-- or write fails closed.

SET LOCAL ROLE appowner;

CREATE TABLE public.oidc_idp_domain_bindings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    idp_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    CONSTRAINT oidc_idp_domain_bindings_pkey PRIMARY KEY (id),
    CONSTRAINT uq_oidc_domain_binding UNIQUE (tenant_id, domain_id),
    CONSTRAINT oidc_idp_domain_bindings_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT oidc_idp_domain_bindings_domain_id_fkey
        FOREIGN KEY (domain_id) REFERENCES public.tenant_privileged_domains(id) ON DELETE CASCADE,
    CONSTRAINT oidc_idp_domain_bindings_idp_id_fkey
        FOREIGN KEY (idp_id) REFERENCES public.oidc_idp_connections(id) ON DELETE CASCADE,
    CONSTRAINT fk_oidc_domain_binding_created_by
        FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL
);

ALTER TABLE public.oidc_idp_domain_bindings OWNER TO appowner;

CREATE INDEX idx_oidc_domain_bindings_tenant
    ON public.oidc_idp_domain_bindings USING btree (tenant_id);
CREATE INDEX idx_oidc_domain_bindings_domain
    ON public.oidc_idp_domain_bindings USING btree (domain_id);
CREATE INDEX idx_oidc_domain_bindings_idp
    ON public.oidc_idp_domain_bindings USING btree (idp_id);

ALTER TABLE public.oidc_idp_domain_bindings ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_domain_bindings_tenant_isolation ON public.oidc_idp_domain_bindings
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_idp_domain_bindings TO appuser;
