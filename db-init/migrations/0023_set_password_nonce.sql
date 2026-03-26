SET LOCAL ROLE appowner;

-- Add set_password_nonce to user_emails to enable one-time-use password-set links.
-- Works the same way as verify_nonce: the link embeds the current value, and the
-- server increments it on successful use, invalidating any copies of the link.
ALTER TABLE user_emails
    ADD COLUMN set_password_nonce integer DEFAULT 1 NOT NULL;
