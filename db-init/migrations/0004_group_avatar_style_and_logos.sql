SET LOCAL ROLE appowner;

-- New enum for group avatar style
CREATE TYPE public.group_avatar_style AS ENUM ('mandala', 'acronym');

-- Add column to tenant_branding
ALTER TABLE public.tenant_branding
    ADD COLUMN group_avatar_style public.group_avatar_style
    NOT NULL DEFAULT 'mandala';

-- New table for per-group custom logos
CREATE TABLE public.group_logos (
    group_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    logo_data bytea NOT NULL,
    logo_mime text NOT NULL,
    updated_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT group_logos_pkey PRIMARY KEY (group_id),
    CONSTRAINT fk_group_logos_group FOREIGN KEY (group_id, tenant_id)
        REFERENCES public.groups(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT chk_group_logo_mime CHECK (
        logo_mime IN ('image/png', 'image/svg+xml') AND length(logo_mime) <= 20
    )
);

-- RLS policy
ALTER TABLE public.group_logos ENABLE ROW LEVEL SECURITY;
CREATE POLICY group_logos_tenant_isolation ON public.group_logos
    USING (tenant_id = (
        NULLIF(current_setting('app.tenant_id', true), '')::uuid
    ));
