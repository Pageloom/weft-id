-- Remove the mandala option from group avatar styles.
-- All groups now use the acronym avatar style exclusively.
-- migration-safety: ignore

SET LOCAL ROLE appowner;

-- Convert any existing mandala rows to acronym
UPDATE tenant_branding
SET group_avatar_style = 'acronym'
WHERE group_avatar_style = 'mandala';

-- Convert column from enum to text so we can drop the enum type
ALTER TABLE tenant_branding
    ALTER COLUMN group_avatar_style TYPE text USING group_avatar_style::text;

-- Set default on the text column
ALTER TABLE tenant_branding
    ALTER COLUMN group_avatar_style SET DEFAULT 'acronym';

-- Add CHECK constraint excluding mandala
ALTER TABLE tenant_branding
    ADD CONSTRAINT group_avatar_style_check CHECK (group_avatar_style IN ('acronym'));

-- Drop the now-unused enum type
DROP TYPE IF EXISTS public.group_avatar_style;
