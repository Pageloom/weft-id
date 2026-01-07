-- Migration 00022: Remove auth_method column from users
--
-- Simplifies authentication model:
-- - saml_idp_id = NULL → password user
-- - saml_idp_id = UUID → IdP user
--
-- Domain binding now immediately assigns all matching users to the IdP.
-- No more "automatic" routing - every user is explicitly password or IdP.

-- =============================================================================
-- Drop auth_method column
-- =============================================================================

ALTER TABLE users DROP COLUMN IF EXISTS auth_method;
