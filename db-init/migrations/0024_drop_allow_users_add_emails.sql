-- migration-safety: ignore
SET LOCAL ROLE appowner;

-- Email management is now admin-only; the toggle is no longer needed.
-- Safe: application code no longer references this column (deployed in same release).
ALTER TABLE tenant_security_settings DROP COLUMN allow_users_add_emails;
