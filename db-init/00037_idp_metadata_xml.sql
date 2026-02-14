-- Store raw IdP metadata XML so we can always parse advertised attributes
-- and other metadata details without re-fetching.

BEGIN;

ALTER TABLE saml_identity_providers
    ADD COLUMN IF NOT EXISTS metadata_xml TEXT DEFAULT NULL;

COMMENT ON COLUMN saml_identity_providers.metadata_xml IS
    'Raw SAML metadata XML from import or last refresh. Used to display advertised attributes.';

COMMIT;
