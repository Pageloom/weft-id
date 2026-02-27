SET LOCAL ROLE appowner;

ALTER TABLE public.group_graph_layouts
    ADD CONSTRAINT chk_group_graph_layouts_positions_size
    CHECK (length(positions::text) <= 524288);
