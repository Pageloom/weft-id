-- Replace sequential integer nonces with random tokens.
--
-- verify_nonce and set_password_nonce were sequential integers starting at 1,
-- making them trivially guessable if the email_id UUID was leaked. Random
-- tokens eliminate that risk.
--
-- migration-safety: ignore
-- ALTER COLUMN TYPE acquires ACCESS EXCLUSIVE lock, but the migrate service
-- runs before the app starts so there are no concurrent queries.

SET LOCAL ROLE appowner;

-- Convert verify_nonce from integer to text with random values.
-- gen_random_bytes is evaluated per-row, so each row gets a unique token.
ALTER TABLE user_emails
    ALTER COLUMN verify_nonce TYPE text
        USING encode(gen_random_bytes(24), 'hex'),
    ALTER COLUMN verify_nonce SET DEFAULT encode(gen_random_bytes(24), 'hex');

-- Convert set_password_nonce from integer to text with random values.
ALTER TABLE user_emails
    ALTER COLUMN set_password_nonce TYPE text
        USING encode(gen_random_bytes(24), 'hex'),
    ALTER COLUMN set_password_nonce SET DEFAULT encode(gen_random_bytes(24), 'hex');
