SET LOCAL ROLE appowner;

-- Add CHECK constraint to user_emails.email column to enforce max length of 320 characters
-- This provides a database-level backstop for the application's Pydantic EmailStr validation
ALTER TABLE public.user_emails
ADD CONSTRAINT chk_user_emails_email_length CHECK (length(email) <= 320);
