-- Add columns for password change and admin-forced password reset.
--
-- password_reset_required: set by admin, forces password change on next login.
-- password_changed_at: tracks when the password was last changed.
SET LOCAL ROLE appowner;

ALTER TABLE public.users
    ADD COLUMN password_reset_required boolean DEFAULT false NOT NULL;

ALTER TABLE public.users
    ADD COLUMN password_changed_at timestamp with time zone;
