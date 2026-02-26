SET LOCAL ROLE appowner;

-- Change the default group avatar style from mandala to acronym
ALTER TABLE public.tenant_branding
    ALTER COLUMN group_avatar_style SET DEFAULT 'acronym';
