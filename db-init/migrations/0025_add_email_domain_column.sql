-- Add domain column to user_emails for efficient domain-based filtering.
-- Extracts the domain part from the email address (everything after @).
-- migration-safety: ignore

SET LOCAL ROLE appowner;

-- Add nullable column, backfill, then set NOT NULL
ALTER TABLE user_emails ADD COLUMN domain text DEFAULT '';

UPDATE user_emails SET domain = split_part(email::text, '@', 2);

ALTER TABLE user_emails ALTER COLUMN domain SET NOT NULL;

ALTER TABLE user_emails ADD CONSTRAINT chk_user_emails_domain_length
    CHECK (length(domain) <= 253);

-- Index for efficient DISTINCT domain queries and domain-based filtering
CREATE INDEX idx_user_emails_domain ON user_emails (tenant_id, domain);
