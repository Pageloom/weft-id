-- One OIDC link per user per connection.
--
-- A user may hold links to several OIDC connections (social sign-in: GitHub
-- and Google on one account), but at most one per connection. Without this,
-- the email-linking path could attach a second upstream account to a user
-- who is already linked on the same connection.
--
-- Existing duplicates (possible before this constraint) are collapsed to the
-- most recently used link, falling back to the most recently created one.

SET LOCAL ROLE appowner;

DELETE FROM public.oidc_idp_user_links l
USING (
    SELECT id,
           row_number() OVER (
               PARTITION BY idp_id, user_id
               ORDER BY last_used_at DESC NULLS LAST, created_at DESC, id DESC
           ) AS rn
    FROM public.oidc_idp_user_links
) ranked
WHERE l.id = ranked.id
  AND ranked.rn > 1;

ALTER TABLE public.oidc_idp_user_links
    ADD CONSTRAINT uq_oidc_user_link_idp_user UNIQUE (idp_id, user_id);
