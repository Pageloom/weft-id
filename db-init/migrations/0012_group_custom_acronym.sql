-- Add optional custom acronym override for groups.
-- When set, the frontend displays this instead of auto-generated initials.

SET LOCAL ROLE appowner;

ALTER TABLE groups ADD COLUMN acronym varchar(4) DEFAULT NULL;

ALTER TABLE groups ADD CONSTRAINT groups_acronym_length_check
    CHECK (char_length(acronym) <= 4);
