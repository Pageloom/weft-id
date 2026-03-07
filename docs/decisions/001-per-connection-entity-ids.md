# ADR 001: Per-Connection SAML Entity IDs

**Date:** 2026-03-07
**Status:** Accepted

## Context

WeftID is a federation broker. It sits between upstream identity providers (Okta, Entra ID,
Google Workspace) and downstream service providers (any SAML SP). Every connection on both
sides is an independent trust relationship with its own signing certificate, attribute
mapping, and access policy.

SAML entity IDs are the permanent identifiers that bind these trust relationships together.
An IdP and an SP exchange entity IDs during setup and use them to verify every subsequent
message. Changing an entity ID breaks the trust silently: assertions start failing, logins
stop working, and nothing in the SAML spec requires a clear error message.

The original design used one entity ID per tenant per role:

- `urn:weftid:{tenant_id}:sp` (shared by all upstream IdP connections)
- `urn:weftid:{tenant_id}:idp` (shared by all downstream SP connections)

This is the common pattern for terminal IdPs and SPs, where a single organization has one
identity and presents it to all partners. It works fine when you are the endpoint.

A federation broker is not the endpoint. It mediates between many parties. Sharing a single
entity ID across all connections creates two problems:

1. **Collision.** A tenant cannot register the same upstream IdP twice (e.g., two Okta orgs
   during a merger) because entity ID uniqueness checks block the second registration. The
   same applies downstream: two SP registrations pointing at the same application (staging
   and production, or two business units) would collide.

2. **Coupling.** If all connections share an entity ID, rotating the signing certificate for
   one connection means the entity ID's metadata changes for all of them. Partners who did
   not expect the change see validation failures.

## Decision

Each trust relationship gets its own entity ID, scoped by the connection's primary key:

- SP entity ID (presented to a specific upstream IdP): `urn:weftid:{tenant_id}:sp:{idp_registration_id}`
- IdP entity ID (presented to a specific downstream SP): `urn:weftid:{tenant_id}:idp:{sp_registration_id}`

The connection UUID is the row's primary key, assigned at creation and never changed. This
makes entity IDs deterministic, stable, and domain-independent. They survive subdomain
renames, path changes, and infrastructure migrations without breaking any federation trust.

The tenant ID prefix is retained for log readability and debugging (you can tell which
tenant an entity ID belongs to at a glance).

## Consequences

**Malleable but not surprising.** Each connection is fully independent. Adding, removing,
or reconfiguring one connection never affects another. A tenant can register the same
upstream IdP multiple times, connect the same downstream SP through different policies,
and rotate certificates per-connection. This is the flexibility a federation broker needs.

At the same time, the format is predictable. Given a connection ID, you can reconstruct the
entity ID without a database lookup. The URN scheme makes it clear that these are WeftID
identifiers (not URLs that might be fetched), and the structure is self-documenting.

**Tenant-level metadata goes away.** With per-connection entity IDs, there is no single
"tenant IdP entity ID" to put in a tenant-level metadata document. The tenant-level
metadata endpoint (`GET /saml/idp/metadata`) was removed. Each SP has its own metadata
endpoint (`GET /saml/idp/metadata/{sp_id}`) which returns the correct per-connection
entity ID and signing certificate.

**Upstream IdP entity ID uniqueness constraint dropped.** The `saml_identity_providers`
table stored the upstream IdP's entity ID with a unique constraint per tenant. Since the
whole point is to allow the same upstream IdP to be registered multiple times, this
constraint was removed (migration `0009_drop_idp_entity_id_unique.sql`).

**Breaking change for existing trust relationships.** Any SP or IdP configured with the
old per-tenant entity ID format will stop matching after this change. This is acceptable
pre-1.0. Post-1.0, this would require a major version bump per the versioning policy.

## Precedent

- **Citrix Cloud** uses "scoped entity IDs" unique per connection.
- **PingFederate** uses "Virtual Server IDs" for the same purpose.
- Both address the same limitation that per-tenant entity IDs create for federation broker
  deployments.
