SET LOCAL ROLE appowner;

CREATE TABLE IF NOT EXISTS public.group_graph_layouts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    node_ids text NOT NULL DEFAULT '' CONSTRAINT chk_group_graph_layouts_node_ids_length CHECK (length(node_ids) <= 65535),
    positions jsonb NOT NULL DEFAULT '{}',
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_graph_layouts_pkey PRIMARY KEY (id),
    CONSTRAINT uq_group_graph_layout UNIQUE (tenant_id, user_id),
    CONSTRAINT group_graph_layouts_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE,
    CONSTRAINT group_graph_layouts_user_fkey
        FOREIGN KEY (user_id, tenant_id) REFERENCES public.users(id, tenant_id) ON DELETE CASCADE
);

ALTER TABLE public.group_graph_layouts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'group_graph_layouts'
        AND policyname = 'group_graph_layouts_tenant_isolation'
    ) THEN
        CREATE POLICY group_graph_layouts_tenant_isolation
            ON public.group_graph_layouts
            USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
            WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);
    END IF;
END $$;
