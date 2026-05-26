-- ---------------------------------------------------------------------------
-- Partial unique index on upstream externalId per IdP connection.
--
-- Inbound SCIM stores Okta/Entra's externalId in `user_idp_attributes` under
-- the reserved `__external_id` key (see app/database/user_idp_attributes.py).
-- The table's primary key is (user_id, idp_id, attribute_key), which allows
-- two different users to claim the same externalId for the same IdP — a
-- race window the merge function in `services/scim/inbound_write.py` cannot
-- close at the application layer (the lookups + writes don't share a
-- transaction).
--
-- This partial unique index enforces "one externalId per IdP" at the DB
-- level, so concurrent identical SCIM POSTs deterministically collide and
-- the merge function can catch the UniqueViolation and retry the lookup.
--
-- migration-safety: ignore (write lock on user_idp_attributes is sub-millisecond
-- in practice: this table holds one row per (user, idp, attribute_key) and
-- the inbound SCIM write path is the only producer. CONCURRENTLY would be
-- required if this index targeted a high-write table, but here both the
-- size and write rate are bounded by directory churn.)
-- ---------------------------------------------------------------------------

SET LOCAL ROLE appowner;

CREATE UNIQUE INDEX user_idp_external_id_unique
    ON public.user_idp_attributes (idp_id, value)
    WHERE attribute_key = '__external_id';
