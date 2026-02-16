-- ============================================================================
-- Reactivation Requests
--
-- This migration creates the reactivation_requests table for handling user
-- requests to reactivate their inactivated accounts.
--
-- Flow:
--   1. Inactivated user attempts login → sees "Account Inactivated" page
--   2. User requests reactivation → email verification required
--   3. After verification → request created, admins notified
--   4. Admin approves/denies → user notified
--
-- Design principles:
--   - One pending request per user per tenant (UNIQUE constraint)
--   - Tracks decision history for audit
--   - Denial prevents future requests until cleared
-- ============================================================================
\set ON_ERROR_STOP on

BEGIN;
SET LOCAL ROLE appowner;

-- ============================================================================
-- TABLE: reactivation_requests
-- ============================================================================

CREATE TABLE IF NOT EXISTS reactivation_requests
(
    id           UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id      UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by   UUID                 REFERENCES users (id),
    decided_at   TIMESTAMPTZ,
    decision     TEXT                 CHECK (decision IN ('approved', 'denied')),
    UNIQUE (tenant_id, user_id)
);

COMMENT ON TABLE reactivation_requests IS
    'Pending and historical reactivation requests from inactivated users.';

COMMENT ON COLUMN reactivation_requests.decision IS
    'Final decision: approved (user reactivated) or denied (request rejected).';

-- ============================================================================
-- ADD denial tracking to users table
-- ============================================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS reactivation_denied_at TIMESTAMPTZ DEFAULT NULL;

COMMENT ON COLUMN users.reactivation_denied_at IS
    'Timestamp when a reactivation request was denied. Prevents future requests until cleared.';

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Query pending requests by tenant
CREATE INDEX IF NOT EXISTS idx_reactivation_requests_pending
    ON reactivation_requests (tenant_id)
    WHERE decision IS NULL;

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE reactivation_requests TO appuser;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE reactivation_requests ENABLE ROW LEVEL SECURITY;

DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM pg_policies
                       WHERE schemaname = 'public'
                         AND tablename = 'reactivation_requests'
                         AND policyname = 'reactivation_requests_tenant_isolation') THEN
            CREATE POLICY reactivation_requests_tenant_isolation ON reactivation_requests
                USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
                WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
        END IF;
    END
$$;

COMMIT;
