-- Token introspection (RFC 7662) for resource servers.
--
-- A client may always introspect the tokens issued to it. With
-- can_introspect_tenant_tokens an admin lets one client introspect every token
-- in the tenant, which makes it a resource server (typically an API backend
-- that receives tokens issued to other apps). Off by default.

SET LOCAL ROLE appowner;

ALTER TABLE public.oauth2_clients
    ADD COLUMN can_introspect_tenant_tokens boolean DEFAULT false NOT NULL;
