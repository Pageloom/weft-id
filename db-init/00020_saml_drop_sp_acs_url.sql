-- Migration: Remove per-IdP sp_acs_url column
--
-- The SAML implementation now uses a single generic ACS URL for all IdPs
-- (standard SAML practice). The ACS URL is derived from sp_entity_id:
--   sp_entity_id = "{base_url}/saml/metadata"
--   acs_url = "{base_url}/saml/acs"
--
-- This migration removes the sp_acs_url column and its unique constraint.

-- Drop the unique constraint first
ALTER TABLE saml_identity_providers
DROP CONSTRAINT IF EXISTS uq_saml_idp_tenant_sp_acs_url;

-- Drop the column
ALTER TABLE saml_identity_providers
DROP COLUMN IF EXISTS sp_acs_url;
