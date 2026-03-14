-- Add custom logo support for service providers
SET LOCAL ROLE appowner;

-- Add composite unique constraint on (id, tenant_id) for FK references
ALTER TABLE public.service_providers
    ADD CONSTRAINT service_providers_id_tenant_unique UNIQUE (id, tenant_id);

CREATE TABLE public.sp_logos (
    sp_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    logo_data bytea NOT NULL,
    logo_mime text NOT NULL,
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT sp_logos_pkey PRIMARY KEY (sp_id),
    CONSTRAINT fk_sp_logos_sp FOREIGN KEY (sp_id, tenant_id)
        REFERENCES public.service_providers(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_sp_logo_mime CHECK (
        logo_mime IN ('image/png', 'image/svg+xml') AND length(logo_mime) <= 20
    )
);

ALTER TABLE public.sp_logos ENABLE ROW LEVEL SECURITY;

CREATE POLICY sp_logos_tenant_isolation ON public.sp_logos
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.sp_logos TO appuser;
