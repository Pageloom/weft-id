-- Drop the unique constraint on (tenant_id, entity_id) for saml_identity_providers.
-- Per-connection entity IDs mean a tenant can register the same upstream IdP
-- multiple times (e.g., during merger consolidation), so the upstream IdP's
-- entity_id is no longer required to be unique within a tenant.
SET LOCAL ROLE appowner;

ALTER TABLE saml_identity_providers
    DROP CONSTRAINT uq_saml_idp_tenant_entity_id;
