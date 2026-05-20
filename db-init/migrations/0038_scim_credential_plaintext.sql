-- migration-safety: ignore (additive column on small admin table; safe at any size)
--
-- NOTE: this migration intentionally does NOT `SET LOCAL ROLE appowner`.
-- The sp_scim_credentials table is owned by postgres (a quirk of migration
-- 0036). DDL ownership requires the table owner; running as the connection
-- user (postgres superuser) covers it. Mirrors migration 0037's approach.

-- Add encrypted plaintext storage to sp_scim_credentials so the outbound
-- push worker can recover the bearer token it must send to the downstream
-- SP. token_hash (added in 0036) verifies inbound presentation; this new
-- column carries the value we present outbound. Fernet ciphertext is
-- variable-width text; we store as BYTEA to avoid encoding surprises.
ALTER TABLE sp_scim_credentials
    ADD COLUMN IF NOT EXISTS encrypted_plaintext BYTEA;
