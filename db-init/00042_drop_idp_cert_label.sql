-- ============================================================================
-- Drop label and is_active columns from idp_certificates
--
-- The label column distinguished "From metadata" vs manually added certs.
-- The is_active column allowed admins to deactivate individual certs.
-- Since all IdP certificates are now managed exclusively through metadata
-- sync, both columns are unnecessary. All certs in the table are valid.
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

ALTER TABLE idp_certificates DROP COLUMN IF EXISTS label;
ALTER TABLE idp_certificates DROP COLUMN IF EXISTS is_active;

-- Drop the index that referenced is_active
DROP INDEX IF EXISTS idx_idp_certificates_idp_active;

-- Replace with a simple index on idp_id
CREATE INDEX IF NOT EXISTS idx_idp_certificates_idp
    ON idp_certificates (idp_id);

COMMIT;
