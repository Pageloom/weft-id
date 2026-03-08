-- Domain-group links: auto-assign users to groups based on privileged email domains.
-- Junction table linking tenant_privileged_domains to groups. When a user's email
-- matches a linked domain (at creation or verification), they are automatically
-- added to the linked groups.
-- migration-safety: ignore (concurrent indexes not needed on new table)
SET LOCAL ROLE appowner;

CREATE TABLE public.domain_group_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    group_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    CONSTRAINT domain_group_links_pkey PRIMARY KEY (id),
    CONSTRAINT uq_domain_group_link UNIQUE (domain_id, group_id),
    CONSTRAINT domain_group_links_tenant_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT domain_group_links_domain_fkey FOREIGN KEY (domain_id) REFERENCES public.tenant_privileged_domains(id) ON DELETE CASCADE,
    CONSTRAINT domain_group_links_group_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE,
    CONSTRAINT fk_domain_group_links_created_by FOREIGN KEY (created_by, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE SET NULL
);

ALTER TABLE public.domain_group_links OWNER TO appowner;

CREATE INDEX idx_domain_group_links_tenant ON public.domain_group_links USING btree (tenant_id);
CREATE INDEX idx_domain_group_links_domain ON public.domain_group_links USING btree (domain_id);
CREATE INDEX idx_domain_group_links_group ON public.domain_group_links USING btree (group_id);

ALTER TABLE public.domain_group_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY domain_group_links_isolation ON public.domain_group_links
    USING ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid))
    WITH CHECK ((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.domain_group_links TO appuser;
