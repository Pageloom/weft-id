-- ============================================================================
-- Event Log Metadata Deduplication
--
-- This migration implements metadata deduplication for event logs by:
-- 1. Creating event_log_metadata table for deduplicated metadata storage
-- 2. Moving metadata from event_logs to the new table
-- 3. Replacing metadata JSONB column with metadata_hash VARCHAR foreign key
--
-- Metadata structure:
--   - 4 required request fields: remote_address, user_agent, device, session_id_hash
--   - All 4 keys always present (even if null)
--   - Events may add custom fields on top of the 4 required fields
--   - Hash computed on entire metadata object (required + custom fields)
--
-- Backward compatibility:
--   - Existing events get migrated to system metadata record (all nulls)
--   - Events with existing metadata preserve their custom fields
-- ============================================================================
\set ON_ERROR_STOP on

-- Switch to appowner role for DDL
set local role appowner;

-- ============================================================================
-- TABLE: event_log_metadata
-- ============================================================================

CREATE TABLE IF NOT EXISTS event_log_metadata
(
    metadata_hash VARCHAR(32) PRIMARY KEY,  -- MD5 hash of deterministic JSON
    metadata      JSONB NOT NULL,           -- Full metadata (request fields + custom data)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE event_log_metadata IS
    'Deduplicated metadata storage for event logs. Hash computed on entire metadata object.';

COMMENT ON COLUMN event_log_metadata.metadata_hash IS
    'MD5 hash of json.dumps(metadata, sort_keys=True, separators=('','','':''))';

COMMENT ON COLUMN event_log_metadata.metadata IS
    'Metadata object with 4 required request fields (remote_address, user_agent, device, session_id_hash) plus optional custom event data.';

-- Index for lookups (though primary key already provides this)
CREATE INDEX IF NOT EXISTS idx_event_log_metadata_created
    ON event_log_metadata (created_at DESC);

-- ============================================================================
-- EXPLICIT GRANTS
-- ============================================================================

GRANT SELECT, INSERT ON TABLE event_log_metadata TO appuser;

-- ============================================================================
-- MODIFY event_logs TABLE
-- ============================================================================

-- Add metadata_hash column (nullable initially for backfill)
ALTER TABLE event_logs
    ADD COLUMN IF NOT EXISTS metadata_hash VARCHAR(32);

-- ============================================================================
-- BACKFILL: Migrate existing metadata to event_log_metadata table
-- ============================================================================

DO
$$
DECLARE
    system_metadata_obj JSONB;
    system_metadata_hash TEXT;
    event_record RECORD;
    merged_metadata JSONB;
    computed_hash TEXT;
    events_processed INT := 0;
BEGIN
    -- Create system metadata object (all 4 request fields as null)
    system_metadata_obj := '{"device":null,"remote_address":null,"session_id_hash":null,"user_agent":null}'::jsonb;

    -- Compute hash using MD5 of deterministic JSON
    -- Note: JSONB keys are sorted alphabetically by PostgreSQL, matching Python's sort_keys=True
    -- The ::text conversion produces compact JSON matching separators=(',', ':')
    system_metadata_hash := md5(system_metadata_obj::text);

    -- Insert system metadata record
    INSERT INTO event_log_metadata (metadata_hash, metadata)
    VALUES (system_metadata_hash, system_metadata_obj)
    ON CONFLICT (metadata_hash) DO NOTHING;

    RAISE NOTICE 'Created system metadata record with hash: %', system_metadata_hash;

    -- Migrate existing events one by one
    FOR event_record IN SELECT id, metadata FROM event_logs WHERE metadata_hash IS NULL
    LOOP
        IF event_record.metadata IS NULL THEN
            -- No existing metadata, use system metadata hash
            UPDATE event_logs
            SET metadata_hash = system_metadata_hash
            WHERE id = event_record.id;
        ELSE
            -- Has existing custom metadata, merge with system fields
            merged_metadata := system_metadata_obj || event_record.metadata;
            computed_hash := md5(merged_metadata::text);

            -- Insert merged metadata (if not already exists)
            INSERT INTO event_log_metadata (metadata_hash, metadata)
            VALUES (computed_hash, merged_metadata)
            ON CONFLICT (metadata_hash) DO NOTHING;

            -- Update event to reference the merged metadata
            UPDATE event_logs
            SET metadata_hash = computed_hash
            WHERE id = event_record.id;
        END IF;

        events_processed := events_processed + 1;
    END LOOP;

    RAISE NOTICE 'Backfilled % existing events with metadata hashes', events_processed;
END
$$;

-- ============================================================================
-- MAKE FOREIGN KEY AND NOT NULL CONSTRAINTS
-- ============================================================================

-- Add foreign key constraint to event_log_metadata
ALTER TABLE event_logs
    ADD CONSTRAINT fk_event_logs_metadata_hash
    FOREIGN KEY (metadata_hash)
    REFERENCES event_log_metadata(metadata_hash)
    ON DELETE RESTRICT;  -- Prevent deletion of metadata records in use

-- Make metadata_hash NOT NULL (now that all rows have values)
ALTER TABLE event_logs
    ALTER COLUMN metadata_hash SET NOT NULL;

-- ============================================================================
-- DROP OLD COLUMN
-- ============================================================================

-- Drop the old metadata column from event_logs (data now in event_log_metadata)
ALTER TABLE event_logs DROP COLUMN IF EXISTS metadata;

-- Update table comment to reflect new structure
COMMENT ON COLUMN event_logs.metadata_hash IS
    'Foreign key to event_log_metadata. All metadata (request + custom) stored in metadata table.';

-- ============================================================================
-- CREATE INDEX ON metadata_hash
-- ============================================================================

-- Index for JOIN performance (though FK already creates one)
CREATE INDEX IF NOT EXISTS idx_event_logs_metadata_hash
    ON event_logs (metadata_hash);
