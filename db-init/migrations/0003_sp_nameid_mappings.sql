-- Per-SP persistent NameID mappings
--
-- Stores opaque persistent identifiers for user-SP pairs.
-- Used when an SP's nameid_format is set to persistent.

SET LOCAL ROLE appowner;

CREATE TABLE public.sp_nameid_mappings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    sp_id uuid NOT NULL,
    nameid_value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sp_nameid_mappings_pkey PRIMARY KEY (id),
    CONSTRAINT uq_sp_nameid_mapping UNIQUE (tenant_id, user_id, sp_id),
    CONSTRAINT sp_nameid_mappings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT sp_nameid_mappings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT sp_nameid_mappings_sp_id_fkey FOREIGN KEY (sp_id) REFERENCES public.service_providers(id) ON DELETE CASCADE,
    CONSTRAINT chk_sp_nameid_value_length CHECK (length(nameid_value) <= 255)
);

CREATE INDEX idx_sp_nameid_mappings_tenant ON public.sp_nameid_mappings USING btree (tenant_id);
CREATE INDEX idx_sp_nameid_mappings_user_sp ON public.sp_nameid_mappings USING btree (user_id, sp_id);

ALTER TABLE public.sp_nameid_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY sp_nameid_mappings_tenant_isolation ON public.sp_nameid_mappings
    USING ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid))
    WITH CHECK ((tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), ''::text))::uuid));

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.sp_nameid_mappings TO appuser;
