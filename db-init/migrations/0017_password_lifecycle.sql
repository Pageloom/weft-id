-- Password lifecycle hardening columns
-- Adds HIBP monitoring data and policy-at-set tracking to users table.
SET LOCAL ROLE appowner;

-- HIBP continuous monitoring: store the SHA-1 prefix (first 5 hex chars)
-- and an HMAC of the full SHA-1 at password-set time. A background job
-- periodically queries HIBP with the prefix and compares HMACs to detect
-- passwords that appear in breaches after they were set.
ALTER TABLE users ADD COLUMN hibp_prefix char(5);
ALTER TABLE users ADD COLUMN hibp_check_hmac varchar(64);

-- Policy compliance enforcement: store the password policy in effect when
-- the password was set. When an admin tightens the policy, users whose
-- stored values are weaker than the new policy are flagged for reset.
ALTER TABLE users ADD COLUMN password_policy_length_at_set integer;
ALTER TABLE users ADD COLUMN password_policy_score_at_set integer;
