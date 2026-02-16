-- Migration: Add enabled column to service_providers for lifecycle management
-- Allows temporarily disabling SPs without deleting them

BEGIN;
SET LOCAL ROLE appowner;

ALTER TABLE service_providers ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;

COMMIT;
