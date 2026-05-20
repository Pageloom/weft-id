-- migration-safety: ignore (drop column on small admin table; safe at any size)
--
-- NOTE: this migration intentionally does NOT `SET LOCAL ROLE appowner`.
-- The sp_scim_credentials table is owned by postgres (a quirk of migration
-- 0036). DDL ownership requires the table owner; running as the connection
-- user (postgres superuser) covers it. Mirrors migrations 0037 and 0038.

-- Drop the unused token_hash column from sp_scim_credentials.
--
-- token_hash was originally added in migration 0036 as a defensive shape for
-- a future inbound SCIM-server flow (where WeftID would verify bearer tokens
-- presented to it). The current outbound design never reads token_hash --
-- the worker recovers bearer tokens via encrypted_plaintext (added in 0038)
-- and presents them to downstream SPs. The hash column has been dead weight
-- since iter 5 landed.
--
-- When inbound SCIM support arrives, the hash column will be rebuilt as part
-- of that work (likely with a tighter shape that captures presentation
-- metadata too).
DROP INDEX IF EXISTS sp_scim_credentials_token_hash_key;
ALTER TABLE sp_scim_credentials DROP COLUMN IF EXISTS token_hash;
