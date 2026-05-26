-- ---------------------------------------------------------------------------
-- users.updated_at: track last mutation timestamp.
--
-- Required for SCIM 2.0 `meta.lastModified` (RFC 7643 §3.1), which inbound
-- SCIM writes (iteration 3) need to populate accurately for vendor clients
-- to detect changes. Read endpoints already prefer `updated_at` over
-- `created_at` when present.
--
-- Backfill existing rows with `created_at` so `lastModified` is at minimum
-- the row's birth time rather than NULL.
--
-- Trigger keeps `updated_at` accurate without requiring every UPDATE site
-- to be retrofitted explicitly. The SCIM write service still recomputes
-- and stores its own value as belt-and-braces, but the trigger covers
-- legacy update paths (admin profile edit, SAML attribute sync, etc).
-- ---------------------------------------------------------------------------

SET LOCAL ROLE appowner;

ALTER TABLE public.users
    ADD COLUMN updated_at timestamp with time zone NOT NULL DEFAULT now();

-- Backfill -- existing rows keep `created_at` as their effective last-modified.
UPDATE public.users SET updated_at = created_at;

CREATE OR REPLACE FUNCTION public.update_users_updated_at()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

ALTER FUNCTION public.update_users_updated_at() OWNER TO appowner;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION public.update_users_updated_at();
