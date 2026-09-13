-- migration-safety: ignore (partial unique index predicate change requires
-- DROP + CREATE; the groups table is small and the runner wraps this in a
-- transaction, so CONCURRENTLY is not available)
--
-- OIDC upstream group claim handling.
--
-- 1. groups.oidc_connection_id: an IdP-type group can now be sourced from an
--    OIDC upstream connection instead of a SAML identity provider. The two
--    source columns are mutually exclusive (chk_groups_single_source). The FK
--    cascades: an OIDC group cannot outlive its connection (the service layer
--    deletes the groups first so the removals are audited; the cascade is the
--    database-level guarantee).
--
-- 2. Unique-name indexes are re-scoped per source. WeftID-managed groups are
--    unique by name within the tenant only when they have NO source; groups
--    from each OIDC connection are unique by name within that connection,
--    mirroring idx_groups_idp_name_unique for SAML.
--
-- 3. oidc_idp_connections.group_claim_name_key: when the group claim is a
--    list of objects, the key holding the group name (defaults to "name" at
--    read time when NULL).

SET LOCAL ROLE appowner;

ALTER TABLE public.groups
    ADD COLUMN oidc_connection_id uuid;

ALTER TABLE public.groups
    ADD CONSTRAINT fk_groups_oidc_connection
    FOREIGN KEY (oidc_connection_id) REFERENCES public.oidc_idp_connections(id) ON DELETE CASCADE;

ALTER TABLE public.groups
    ADD CONSTRAINT chk_groups_single_source
    CHECK ((idp_id IS NULL) OR (oidc_connection_id IS NULL));

CREATE INDEX idx_groups_oidc_connection_id
    ON public.groups USING btree (oidc_connection_id)
    WHERE (oidc_connection_id IS NOT NULL);

CREATE UNIQUE INDEX idx_groups_oidc_name_unique
    ON public.groups (tenant_id, oidc_connection_id, name)
    WHERE (oidc_connection_id IS NOT NULL);

DROP INDEX IF EXISTS public.idx_groups_weftid_name_unique;
CREATE UNIQUE INDEX idx_groups_weftid_name_unique
    ON public.groups (tenant_id, name)
    WHERE (idp_id IS NULL AND oidc_connection_id IS NULL);

ALTER TABLE public.oidc_idp_connections
    ADD COLUMN group_claim_name_key text;

ALTER TABLE public.oidc_idp_connections
    ADD CONSTRAINT chk_oidc_connection_group_claim_name_key_length
    CHECK ((group_claim_name_key IS NULL) OR (length(group_claim_name_key) <= 100));
