-- migration-safety: ignore (new table; indexes on empty tables cannot block writes)
SET LOCAL ROLE appowner;

-- ---------------------------------------------------------------------------
-- sp_scim_remote_ids: WeftID UUID -> SP-assigned SCIM `id` mapping
-- ---------------------------------------------------------------------------
--
-- Background: WeftID currently uses its own UUID as the SCIM `id` everywhere
-- (POST/PUT/PATCH/DELETE paths, Group `members[].value`, `$ref`). The SCIM 2.0
-- spec (RFC 7644 §3.3, §3.7) says the server MINTS the `id` on POST and the
-- client must use that server-assigned id in subsequent references. Most
-- spec-compliant receivers (Authentik, Entra, others) honour their own minted
-- id and key member-resolution on it, so WeftID's existing "UUID-as-id"
-- contract silently drops group members downstream.
--
-- This table introduces a per-(sp, resource) indirection: WeftID's UUID is
-- the externalId; `remote_id` is the SP-side canonical id captured from the
-- POST response. PUT/PATCH/DELETE paths and Group `members[].value` use
-- `remote_id` when one exists, with WeftID UUID as a backwards-compatible
-- fallback for unmapped rows.

CREATE TABLE sp_scim_remote_ids (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sp_id UUID NOT NULL REFERENCES service_providers(id) ON DELETE CASCADE,
    resource_type VARCHAR(10) NOT NULL,
    weftid_id UUID NOT NULL,
    remote_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_sp_scim_remote_ids_resource_type
        CHECK (resource_type IN ('user', 'group')),
    CONSTRAINT chk_sp_scim_remote_ids_remote_id_nonempty
        CHECK (length(remote_id) > 0),
    CONSTRAINT uq_sp_scim_remote_ids_target
        UNIQUE (sp_id, resource_type, weftid_id)
);

CREATE INDEX sp_scim_remote_ids_tenant_idx
    ON sp_scim_remote_ids (tenant_id);

-- Reverse lookup: given a SCIM `id` echoed by the receiver, find the WeftID
-- resource. Useful for inbound webhooks in a future iteration; cheap to add now.
CREATE INDEX sp_scim_remote_ids_reverse_idx
    ON sp_scim_remote_ids (sp_id, resource_type, remote_id);

ALTER TABLE sp_scim_remote_ids ENABLE ROW LEVEL SECURITY;

CREATE POLICY sp_scim_remote_ids_tenant_isolation
    ON sp_scim_remote_ids
    FOR ALL
    TO appuser
    USING (tenant_id = (current_setting('app.tenant_id', true))::uuid)
    WITH CHECK (tenant_id = (current_setting('app.tenant_id', true))::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON sp_scim_remote_ids TO appuser;
