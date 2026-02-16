-- ============================================================================
-- User Profile Security Settings
--
-- This migration adds security settings to control what regular users can do
-- with their own profiles. Super admins are always exempt from these restrictions.
--
-- Changes:
--   1) Add columns to tenant_security_settings:
--      - allow_users_edit_profile (default true) - whether users can edit name
--      - allow_users_add_emails (default true) - whether users can add alt emails
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- ALTER TABLE
-- ============================================================================

ALTER TABLE tenant_security_settings
    ADD COLUMN IF NOT EXISTS allow_users_edit_profile BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS allow_users_add_emails   BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN tenant_security_settings.allow_users_edit_profile IS
    'Whether regular users can edit their own profile details (name). Super admins are always allowed. Default is true.';

COMMENT ON COLUMN tenant_security_settings.allow_users_add_emails IS
    'Whether regular users can add alternative email addresses to their account. Super admins are always allowed. Default is true.';

COMMIT;
