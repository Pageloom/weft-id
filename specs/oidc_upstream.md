# OIDC Upstream IdP Support (Generic + Google + Entra)

**Slug**: `oidc_upstream`
**Backlog item**: OIDC Upstream IdP Support (with Entra, Google, GitHub, Okta Presets)
**Branch**: `oidc-upstream`
**Created**: 2026-08-30
**Revised**: 2026-08-30 (plan review -- re-split into 8 iterations, column set settled,
cross-cutting concerns added)
**Status**: In progress -- Iteration 3 of 8

## Context

WeftID currently accepts only SAML 2.0 as an upstream federation protocol. This feature adds a
generic OIDC connector (authorization code + PKCE) so WeftID can consume OIDC IdPs, with thin
Google and Entra presets. It is the remaining half of Phase 1 (functional OIDC in both directions)
of the Recommended Path Forward in `.claude/BACKLOG.md`; the downstream OIDC provider shipped in
1.11.0 (see `ITERATION_oidc_provider.md`).

This is a **peer protocol** to the existing SAML IdP support, not a replacement. Both share the
same downstream user/group plumbing (JIT provisioning, attribute mirroring, privileged domain
routing). The SAML IdP surface (`saml_identity_providers`, `app/services/saml/`,
`app/routers/saml/`, `app/routers/saml/admin/`) is the structural template.

### Scope decisions (2026-08-30, user-confirmed)

- **Presets**: Generic + Google + Entra. GitHub and Okta deferred (Okta tenants almost always work
  via SAML already; GitHub is developer-niche). Apple/Facebook belong to the Phase 2 "Social
  Sign-In Providers" item -- they are non-standard OIDC (Apple: `form_post` + client-secret-as-JWT;
  Facebook: Graph-flavored OAuth2) and need real adapters, not thin presets.
- **Group claims**: **DEFERRED** to a follow-on backlog item. This feature ships claim-to-attribute
  mapping + JIT provisioning only. Per-preset group claim sources (Entra Graph GUID-to-name,
  GitHub orgs/teams API, Okta `groups` claim, Google custom-claim opt-in) are out of scope. The
  connection table still carries a `group_claim_source` column for forward-compat, written by the
  admin form but read by nothing.
- **Admin UI**: Full parallel to the SAML IdP admin surface (list, create/edit form with vendor
  preset picker, detail tabs: details / claim mapping / danger, test-connection).
- **Privileged domain routing**: in scope (OIDC IdPs become binding targets, parallel to SAML).

### Backlog closure (decide before Step 8e)

This feature ships 2 of the backlog item's 5 presets and none of its group-claim criteria. The
backlog item therefore **must not be archived as Complete** at the end of iteration 8. Split it:
archive the core-connector + Generic/Google/Entra criteria as Complete, and open follow-on items
for "OIDC group claim handling" and "GitHub + Okta presets" carrying the unmet criteria forward.

### Current-state facts established during grooming (do not re-derive)

- SAML IdP connection table `saml_identity_providers` (schema.sql:314) is the template: `name`,
  `provider_type` CHECK (`okta|azure_ad|google|generic`), `attribute_mapping jsonb` (default
  `{"email":"email","last_name":"lastName","first_name":"firstName"}`), `is_enabled`, `is_default`,
  `require_platform_mfa`, `jit_provisioning`, `created_by`, timestamps, plus discovery-cache
  columns `metadata_last_fetched_at` / `metadata_fetch_error`. `saml_idp_domain_bindings`
  (schema.sql:380) maps `tenant_privileged_domains` rows to IdPs, unique `(tenant_id, domain_id)`.
- SAML correlates users on **email** (`users.saml_idp_id` FK + `get_user_by_email_for_saml`).
  OIDC correlates on the **`sub` claim** per `(idp_id, sub)` -- a new `oidc_idp_user_links` table.
- JIT provisioning lives in `app/services/saml/provisioning.py` (`jit_provision_user`,
  `authenticate_via_saml`): create user (password NULL), add verified email, link IdP, base group,
  domain groups, mirror attributes, log `user_created_jit`. The OIDC flow mirrors this shape.
- Attribute mirroring: `apply_idp_attributes` in `app/services/users/attributes.py` writes the
  IdP-mirror snapshot (`user_idp_attributes`) + canonical `user_attributes` gated on tenant config
  `mirror_from_idp`. **It validates `idp_id` against `saml_identity_providers`** -- the OIDC path
  needs a parallel variant (see design decisions).
- **Disconnect scrub**: `scrub_canonical_matches_mirror` (`app/services/users/attributes.py:604`)
  clears canonical values that still match the mirror, emitting `cause: idp_disconnect_scrub`. It
  is called from `app/services/saml/providers.py:388` (IdP delete) and
  `app/services/saml/domains.py:517` (domain unbind). The OIDC delete/unbind paths need the same.
- Auth routing: `determine_auth_route` in `app/services/saml/routing.py` is the single decision
  point consulted by `app/routers/auth/_helpers.py` after email verification. It routes on
  `users.saml_idp_id`, domain bindings, and default-IdP JIT. Returns `AuthRouteResult`
  (`app/schemas/saml.py:416`). OIDC IdPs plug in here.
- **Platform MFA is enforced by the SAML ACS, not by `complete_authenticated_login`.**
  `saml_identity_providers.require_platform_mfa` (schema.sql:330) is read via
  `idp_requires_platform_mfa` (`app/services/saml/providers.py:111`) and surfaces as
  `saml_result.requires_mfa`; `app/routers/saml/authentication.py:342` and `:570` then stash
  `pending_mfa_user_id` / `pending_mfa_method` and redirect to `/mfa/verify` **instead of**
  calling `complete_authenticated_login`. Any new federated login path must replicate this or it
  silently bypasses tenant MFA policy.
- **Outbound HTTP must go through the SSRF guard.** `build_safe_client()` in
  `app/utils/safe_http.py` returns an `httpx.Client` with a validating, IP-pinning transport and
  `follow_redirects=False`. Bare `httpx` calls carry a `# ssrf-ok:` waiver comment and exist only
  for fixed public hosts (HIBP). Admin-supplied URLs never qualify.
- **Rate limiting**: `ratelimit.prevent(key, limit, timespan, **fmt)` from `app/utils/ratelimit.py`
  (Memcached-backed). The SAML ACS uses limit=20 / MINUTE window
  (`app/routers/saml/authentication.py:249`, `:411`).
- SAML IdPs have a **full `/api/v1` surface**: `app/routers/api/v1/saml.py` (list/create/get/patch/
  delete/enable/disable/set-default/presets/trust/certs/import, ~20 endpoints) plus
  `app/routers/api/v1/saml_identity_providers.py`. CLAUDE.md rule 8 (API-first) means OIDC needs
  the equivalent, not just an admin UI.
- OIDC provider (downstream) added `pyjwt ^2.10.1`; `httpx ^0.28.1` and `requests >=2.33.0` are
  already dependencies. `cryptography ^50.0.0` present. No OIDC *client* library exists -- the
  connector is built on `httpx` (via `build_safe_client`) + `pyjwt` + `cryptography`.
- Secrets at rest: `encrypt_private_key` / `decrypt_private_key` in `app/utils/saml.py` (Fernet via
  `derive_fernet_key` in `app/utils/crypto.py`) is the established pattern for reversible
  encryption. OAuth2 downstream client secrets are **hashed** (one-way) -- a different pattern; the
  OIDC upstream client secret must be **encrypted** (reversible) because it authenticates outbound.
- Event types: none of the requested OIDC-upstream events exist. SAML naming pattern to mirror:
  `saml_idp_created/updated/deleted/enabled/disabled/set_default`, `saml_domain_bound/unbound/
  rebound`, `user_saml_idp_assigned`, `user_signed_in_saml`, `user_created_jit`. Adding event types
  requires updating `EVENT_TYPE_DESCRIPTIONS`, `EVENT_TYPE_TIERS`, and `event_types.lock`.
- Admin section: `/admin/settings/identity-providers` (pages.py:295) is SUPER_ADMIN, with SAML IdP
  sub-pages. The OIDC admin surface is a parallel section (see design decisions).
- `user_idp_attributes.idp_id` FKs to `saml_identity_providers(id)`; `users.saml_idp_id` likewise.
  OIDC uses parallel tables, not polymorphic columns.
- Route prefix `/auth/oidc/*` is free. The downstream OP lives at `/oauth2/*` and
  `/.well-known/*`; the auth router has no prefix and owns `/login`, `/logout`, etc.

## Design decisions

- **Parallel tables, not generalization** -- OIDC gets its own tables (`oidc_idp_connections`,
  `oidc_idp_user_links`, `oidc_idp_domain_bindings`, `user_oidc_idp_attributes`) mirroring the SAML
  tables. **Rationale**: clean FKs, no polymorphic columns, matches the codebase's per-protocol
  parallel-table precedent (`oidc_signing_keys` vs `saml_sp_certificates`; `saml_idp_domain_bindings`
  stays SAML-only). A parallel `apply_oidc_idp_attributes` mirrors `apply_idp_attributes`.
- **`(idp_id, sub)` correlation** -- `oidc_idp_user_links` maps `(tenant_id, idp_id, sub)` to
  `user_id`, unique `(idp_id, sub)`. **Rationale**: `sub` is the stable OIDC subject; correlation
  survives upstream email changes (SAML's email correlation does not).
- **Client secret encrypted at rest** (reversible), not hashed -- via the existing Fernet helper.
  **Rationale**: the secret authenticates outbound requests to the IdP; WeftID must be able to
  read it back. OAuth2's hashed-at-rest pattern is for verifying inbound client credentials.
- **PyJWT for ID token validation** -- `jwt.decode` against a JWKS fetched from the IdP's
  `jwks_uri` (via `PyJWKSet`, not `PyJWKClient` -- see Iteration 2 decisions log). **Rationale**:
  already a dependency, well-audited, minimal custom crypto surface (same rationale as the OIDC
  provider).
- **All outbound OIDC HTTP goes through `build_safe_client()`** -- discovery, token exchange,
  userinfo, JWKS. **Rationale**: every one of those URLs is admin-supplied or derived from an
  admin-supplied discovery document, which is the textbook SSRF shape. `httpx` direct calls are a
  compliance violation here and would need a `# ssrf-ok:` waiver that does not apply.
- **Connection UUID in the URL, no slug** -- login is `/auth/oidc/{connection_id}/login`, callback
  is `/auth/oidc/{connection_id}/callback`. **Rationale**: matches SAML's `/saml/login/{idp_id}`
  (`app/routers/saml/authentication.py:186`); the redirect URI must be stable and displayable the
  moment the connection is created (the admin pastes it into the IdP console), and a UUID is stable
  by construction. The backlog's `<idp_slug>` wording is descriptive, not a requirement.
- **Platform MFA gate replicated in the OIDC callback** -- the callback must consult a parallel
  `oidc_connection_requires_platform_mfa` and, when true, take the `/mfa/verify` branch rather than
  calling `complete_authenticated_login`. **Rationale**: `complete_authenticated_login` establishes
  the session unconditionally; MFA enforcement lives in the caller. Missing this is a silent
  security regression against a shipped SAML capability.
- **Email linking is opt-in per connection** -- `allow_email_linking` (default **false**). When
  false, an unrecognized `(idp_id, sub)` either JIT-provisions (if enabled) or is rejected; it
  never attaches to an existing WeftID account. When true, linking additionally requires
  `email_verified: true` in the ID token. **Rationale**: silently binding an existing account to a
  new upstream subject on an email match is account takeover when the IdP does not verify emails.
  SAML's email correlation is defensible because the assertion is certificate-verified against
  registered IdP metadata; an OIDC `email` claim carries no such guarantee.
- **Default claim mapping** -- `{"email": "email", "first_name": "given_name",
  "last_name": "family_name"}` (OIDC claim name -> WeftID standard attribute key), configurable per
  connection. **Rationale**: matches the SAML default-mapping shape; JIT needs email + names.
- **Admin section parallel to SAML** -- OIDC IdP admin under its own section
  (`/admin/settings/oidc-identity-providers`), not mixed into the SAML IdP detail tabs.
  **Rationale**: the SAML tabs are protocol-specific (certificates, metadata, SCIM); OIDC has
  different tabs (endpoints, claim mapping, danger). The privileged-domains binding UI is the one
  surface that must show both protocols.
- **`sub` for Entra** -- Entra's `sub` is per-app-anonymous; use the `oid` claim as the correlation
  subject for the Entra preset (per Microsoft guidance). Google uses `sub` directly. Implemented as
  a per-connection `correlation_claim` column the generic connector reads, not a preset code path.
- **Package name `oidc_upstream`** -- `app/services/oidc_upstream/`, `app/database/oidc_upstream/`,
  `app/routers/oidc_upstream/`. **Rationale**: unambiguous that this is the consuming (RP) direction,
  and avoids confusion with the downstream `app/services/oidc/` (OP) package.

### Cross-cutting requirements (apply to every iteration)

These are the three things a per-iteration reading of this plan most easily misses. They are
restated in the iterations that own them, but hold throughout:

1. **SSRF**: no bare `httpx` for any IdP-supplied URL. `build_safe_client()` only. Endpoints read
   *out of* a discovery document are attacker-influenced data too: require `https`, and reject a
   discovery document whose `issuer` does not match the configured issuer.
2. **Platform MFA**: every path that authenticates a user must honor `require_platform_mfa`.
3. **API-first**: every admin capability lands as a `/api/v1` endpoint in the same iteration as the
   service function, ahead of the template that consumes it.

### Scope boundaries (explicitly OUT of this feature)

- Group claim handling / group sync (deferred follow-on).
- GitHub and Okta presets (deferred).
- Apple / Facebook / other consumer IdPs (Phase 2 Social Sign-In item).
- OIDC Hardening items (logout, introspection, revocation, device grant, DCR, pairwise sub, PAR,
  certification) -- separate backlog item.
- Back-channel / RP-initiated logout to upstream IdPs -- OIDC Hardening item.

---

## Iteration 1 -- Data model, database, service CRUD, API
**Status**: Complete
**Completed**: 2026-08-31

The foundation, headless. Full column set (settled now so no later iteration needs a second
migration on the same table), database module, service CRUD with the secret encrypted at rest, and
the `/api/v1` surface. **No templates in this iteration** -- the admin UI lands in Iteration 4,
once the connector has proven the field set.

### Acceptance criteria
- [x] Migration adds `oidc_idp_connections` (tenant-scoped, RLS strict fail-closed) with the full
      column set below. `schema.sql` NOT modified (migration-only convention,
      `.claude/THOUGHT_ERRORS.md:294`).
- [x] Migration adds `oidc_idp_user_links` (tenant-scoped, RLS): `(tenant_id, idp_id, sub,
      user_id)`, UNIQUE `(idp_id, sub)`, FKs to `oidc_idp_connections` (CASCADE) and `users`
      (CASCADE). `sub` max 255.
- [x] Database module `app/database/oidc_upstream/connections.py`: CRUD + list + get-by-issuer +
      get-default + get-enabled, mirroring `app/database/saml/providers.py`. Plus
      `app/database/oidc_upstream/links.py` for the user-links table.
- [x] Service `app/services/oidc_upstream/connections.py`: create/update/delete/list/get,
      set-enabled, set-default, client secret encrypted at rest via the Fernet helper,
      `oidc_connection_requires_platform_mfa` (parallel to
      `app/services/saml/providers.py:111`), and delete-guard + disconnect-scrub mirroring
      `delete_identity_provider` (including the `scrub_canonical_matches_mirror` call at
      `app/services/saml/providers.py:388`, adapted for the OIDC snapshot table once Iteration 5
      creates it -- until then the delete path is scrub-free and Iteration 5 wires it in).
- [x] The service exposes the connection's callback URL (`/auth/oidc/{id}/callback` on the tenant
      host) as a derived read-only field, so the admin can register it at the IdP.
- [x] `/api/v1` endpoints mirroring the SAML shape in `app/routers/api/v1/saml.py`: list, create,
      get, patch, delete, enable, disable, set-default. Client secret is write-only (never returned;
      a `client_secret_set: bool` flag instead). Docstrings document every accepted field.
- [x] Event types added to `event_types.py` (descriptions + tiers) and `event_types.lock`:
      `oidc_idp_connection_created`, `oidc_idp_connection_updated`, `oidc_idp_connection_deleted`,
      `oidc_idp_connection_enabled`, `oidc_idp_connection_disabled`,
      `oidc_idp_connection_set_default` (all admin tier).
- [x] Tests: database CRUD + RLS isolation, service CRUD + encryption-at-rest (secret never stored
      or returned in plaintext) + delete-guard + events, API happy paths + authz + field validation.

### `oidc_idp_connections` column set (settled -- do not defer any of these)

Identity and type: `id`, `tenant_id`, `name` (<=120), `provider_type` CHECK
(`generic|google|entra`).

Endpoints: `issuer` (<=2048), `discovery_url` (<=2048), `authorization_endpoint`,
`token_endpoint`, `userinfo_endpoint`, `jwks_uri` (<=2048 each, nullable -- populated by discovery
or entered manually), `discovery_fetched_at`, `discovery_error` (<=10000). The last two mirror
`metadata_last_fetched_at` / `metadata_fetch_error` on the SAML table.

Credentials: `client_id` (<=255), `client_secret_enc` (<=4096), `scopes` (<=500).

Claims: `claim_mapping jsonb` defaulting to
`{"email": "email", "first_name": "given_name", "last_name": "family_name"}`;
`correlation_claim` (<=50, default `'sub'`); `group_claim_source` (<=255, nullable, reserved for
the deferred group-claims item, written but unread).

Preset config: `hosted_domain` (<=253, nullable -- Google `hd`); `entra_tenant_id` (<=100,
nullable -- the authority is composed from it).

Behavior flags: `is_enabled`, `is_default`, `require_platform_mfa`, `jit_provisioning`,
`allow_email_linking` (all boolean NOT NULL; `allow_email_linking` defaults **false**).

Provenance: `created_by`, `created_at`, `updated_at`.

Constraints: PK, FK `tenant_id` -> `tenants` CASCADE, FK `(created_by, tenant_id)` -> `users`
SET NULL, UNIQUE `(tenant_id, name)`, length CHECKs on every text column, `provider_type` CHECK.
No uniqueness on `issuer`: one tenant may legitimately register two apps against the same issuer.

### What was done
- `db-init/migrations/0057_oidc_upstream_connections.sql` -- Creates `oidc_idp_connections`
  (full settled column set, strict fail-closed RLS, single-default + updated_at triggers) and
  `oidc_idp_user_links` (`(tenant_id, idp_id, sub, user_id)`, UNIQUE `(idp_id, sub)`, CASCADE FKs,
  `sub` <=255). `schema.sql` left untouched per convention.
- `app/database/oidc_upstream/__init__.py` -- Package re-exports.
- `app/database/oidc_upstream/connections.py` -- CRUD + list + get-by-issuer + get-default +
  get-enabled, mirroring `database/saml/providers.py`.
- `app/database/oidc_upstream/links.py` -- User-link table queries (create/get/get-by-idp-sub/
  get-user-id-by-sub/delete/count).
- `app/database/__init__.py` -- Registers the new `oidc_upstream` submodule.
- `app/services/oidc_upstream/__init__.py` -- Package re-exports.
- `app/services/oidc_upstream/connections.py` -- create/update/delete/list/get, set-enabled,
  set-default, `oidc_connection_requires_platform_mfa`, delete-guard (enabled + linked-users),
  client secret encrypted at rest via a purpose-specific Fernet key
  (`derive_fernet_key(b"oidc-upstream-client-secret")`), never returned from any read path.
- `app/schemas/oidc_upstream.py` -- `OIDCConnectionCreate`/`Update`/`Config`/`ListItem`/
  `ListResponse` with `max_length` matching every column CHECK; `client_secret` write-only,
  `client_secret_set` bool on read; derived `callback_url`.
- `app/routers/api/v1/oidc_upstream.py` -- `/api/v1/oidc-upstream/connections` list/create/get/
  patch/delete/enable/disable/set-default, super-admin-gated, docstrings documenting every field.
- `app/main.py` -- Registers the new API router.
- `app/constants/event_types.py` -- Added 6 descriptions + admin-tier entries.
- `app/constants/event_types.lock` -- Added the 6 new event types (sorted).

### Tests added
- `tests/database/test_oidc_upstream.py` -- Connection CRUD, single-default trigger, user-link
  CRUD + UNIQUE constraint, RLS isolation (cross-tenant + UNSCOPED fail-closed).
- `tests/services/test_oidc_upstream.py` -- CRUD, encryption-at-rest (secret never stored/returned
  plaintext), delete-guard, events, MFA flag, secret length bound (3000-char accepted, 3001-char
  rejected at schema).
- `tests/api/test_oidc_upstream.py` -- Happy paths, authz (admin/member 403, unauthenticated 401),
  field validation (422), secret write-only, delete conflict.

### Test review
The test agent found one substantive defect and several low-severity items:

1. **`client_secret` max_length exceeded the encrypted column capacity (Medium)** -- the schema
   accepted up to 4096 chars but Fernet encryption expands a ~3008+ char plaintext past the
   column's 4096 CHECK, producing an unhandled 500 on create/update. **Fixed**: lowered the schema
   `max_length` to 3000 (encrypts to ~4088) with an explanatory comment, and added two tests
   (3000-char accepted, 3001-char rejected at the schema layer).
2. **`_get_base_url` re-implemented the trusted host-derivation helper (Low)** -- **Fixed**:
   replaced with `utils.urls.tenant_base_url`.
3. **`create_link` docstring misleading about duplicate behavior (Low)** -- **Fixed**: corrected
   to state it raises `UniqueViolation` on a duplicate `(idp_id, sub)`.
4. **`created_by NOT NULL` + `ON DELETE SET NULL` contradiction (Low, pre-existing)** -- faithful
   copy of the SAML table's latent pattern; left as-is for consistency, flagged for a follow-up.

Coverage gaps noted (no bug): RLS isolation for `oidc_idp_user_links`, `get_enabled_connections`
ordering / `get_default_connection` disabled-default path, `get_connection_by_issuer` absent case,
update-clearing-nullable-field path, and `set_connection_default` on a disabled connection. These
are deferred to the iterations that consume those paths (Iteration 3 auth flow, Iteration 4 admin
UI).

### Reconceptualisations
None -- the column set and scope held as planned. The only change was a defensive schema bound
correction (client-secret length) that does not alter the data model.

### Decisions log
- **Delete-guard**: blocks deletion when the connection is enabled or has linked users (mirrors
  SAML's guard). The disconnect-scrub is intentionally scrub-free now and wired in Iteration 5,
  per the spec. -- **Context**: the OIDC snapshot table does not exist until Iteration 5. --
  **Rationale**: matches the SAML delete path's shape without referencing a not-yet-created table.
- **Secret encryption**: used a purpose-specific Fernet key distinct from the SAML private-key key,
  rather than reusing `encrypt_private_key`'s `b"saml-key-encryption"` info string. -- **Context**:
  the spec allowed either. -- **Rationale**: keeps the two credential classes cryptographically
  independent.
- **`get_connection_by_issuer`** returns the first match (no issuer uniqueness, per spec) ordered
  by `created_at asc` for deterministic discovery lookups.
- **Migration safety**: added the `-- migration-safety: ignore` directive since both tables are
  created empty in the same migration (indexes can't use `CONCURRENTLY` in-transaction), matching
  the existing `0051_oidc_signing_keys.sql` precedent.
- **Client-secret schema bound lowered to 3000** (from 4096) to account for Fernet encryption
  expansion against the column's 4096 CHECK. -- **Context**: test agent found a valid 3008+ char
  secret would pass Pydantic but violate the DB CHECK. -- **Rationale**: option (a) from the
  finding -- safer and matches the spec's "column <= 4096" intent.

---

## Iteration 2 -- Preset registry + connector core (discovery, JWKS, ID token validation)
**Status**: Complete
**Completed**: 2026-08-31

The crypto-heavy, test-heavy half of the connector, as pure service code with **no routes**. Split
out from the auth flow deliberately: it is independently testable against fixtures and is where the
security bugs live.

### Acceptance criteria
- [x] Preset registry (`app/services/oidc_upstream/presets.py`): each preset supplies discovery/
      authority URL, default scopes, and `correlation_claim`. Generic is the spec-correct default;
      Google is `https://accounts.google.com` / `openid profile email` / `sub`; Entra composes
      `https://login.microsoftonline.com/<entra_tenant_id>/v2.0` / `openid profile email User.Read`
      / `oid`. A preset supplies defaults an admin can override -- no forked code paths.
- [x] Discovery: fetch `/.well-known/openid-configuration` **through `build_safe_client()`**,
      parse the four endpoints + issuer, persist them with `discovery_fetched_at`; failures persist
      `discovery_error` and leave prior values intact. Manual endpoint config is the fallback.
      Refetch is TTL-gated per connection (not per request).
- [x] Discovery response validation: the document's `issuer` must equal the connection's configured
      issuer; every endpoint URL must be `https` (except in `IS_DEV`); a document failing either
      check is rejected and recorded as an error, not persisted.
- [x] JWKS: fetched via `PyJWKClient` over the safe client, cached per connection with a TTL (~1h),
      refreshed once on a signature-validation failure (key rotation), and never fetched per
      request.
- [x] ID token validation: signature against the JWKS, `iss` match, `aud` match (client_id),
      `nonce` match, `exp`/`iat` within tolerance. Each failure mode raises a distinct, typed error.
- [x] Token exchange and userinfo helpers go through `build_safe_client()`.
- [x] Tests against recorded fixtures under `tests/fixtures/oidc/` (no live calls): discovery parse,
      issuer mismatch rejected, non-https endpoint rejected, JWKS cache hit/miss/rotation, ID token
      good path, bad signature, wrong issuer, wrong audience, wrong nonce, expired, missing claims.
- [x] An SSRF test proves a discovery URL pointing at a private/link-local address is refused.

### What was done
- `app/services/oidc_upstream/presets.py` -- Preset registry: Generic (spec default, `sub`), Google
  (`https://accounts.google.com`, `sub`), Entra (composed `login.microsoftonline.com/<tenant_id>/v2.0`,
  `oid` correlation, `User.Read` scope). Presets are defaults only -- no forked code paths.
- `app/services/oidc_upstream/errors.py` -- Typed error hierarchy: `DiscoveryError` (+ issuer-mismatch
  / insecure-endpoint / redirect subclasses), `JwksError`, and `IDTokenValidationError` (+ signature /
  issuer / audience / nonce / expired / not-yet-valid / missing-claims subclasses).
- `app/services/oidc_upstream/discovery.py` -- Fetches `/.well-known/openid-configuration` through
  `build_safe_client()`, validates issuer match + https endpoints, persists the four endpoints +
  `discovery_fetched_at`; failures persist `discovery_error` and leave prior values intact. TTL-gated
  per connection (`force=` bypasses). `userinfo_endpoint` is optional (RECOMMENDED, not REQUIRED).
- `app/services/oidc_upstream/jwks.py` -- Fetches JWKS through the SSRF guard, caches per
  `(tenant, connection)` with a 1h TTL, `refresh_jwks()` for key rotation. Deliberately avoids
  `PyJWKClient` (which does its own unguarded `urllib` fetch). Stale entries are evicted on read.
- `app/services/oidc_upstream/id_token.py` -- Validates signature (RS256, hard-coded alg), `iss`,
  `aud`, `nonce`, `exp`/`iat` with leeway, required-claim presence; single refetch on signature
  failure. Missing-claim errors are mapped to `IDTokenMissingClaimsError` (not signature).
- `app/services/oidc_upstream/token_exchange.py` -- `exchange_code()` (authorization code + PKCE,
  Basic auth) and `fetch_userinfo()`, both through `build_safe_client()`.
- `app/services/oidc_upstream/connections.py` -- Added `decrypt_client_secret()` (reversible, for
  the Iteration 3 token exchange); `delete_connection` now clears the cached JWKS.
- `app/services/oidc_upstream/__init__.py` -- Re-exports the new connector surface, including the
  `errors.py` types.

### Tests added
- `tests/fixtures/oidc/` -- `discovery.json`, `jwks.json`, `private_key.pem` (throwaway RSA-2048
  test key), and a `load_fixture` helper.
- `tests/services/test_oidc_upstream_presets.py` -- preset defaults and correlation-claim selection.
- `tests/services/test_oidc_upstream_discovery.py` -- discovery parse, issuer-mismatch, non-https
  endpoint, redirect, TTL gating, force, optional `userinfo_endpoint`, SSRF refusal.
- `tests/services/test_oidc_upstream_jwks.py` -- cache hit/miss/rotation, error paths, SSRF refusal.
- `tests/services/test_oidc_upstream_id_token.py` -- good path + every failure mode (bad signature,
  wrong issuer/audience/nonce, expired, not-yet-valid, `nbf`-future, missing `sub`/`iss`/`aud`/`exp`/
  `iat`), key-rotation refetch.
- `tests/services/test_oidc_upstream_token_exchange.py` -- token exchange/userinfo success + error
  paths, SSRF refusal of private/link-local addresses.
- `tests/services/test_oidc_upstream.py` -- added `decrypt_client_secret` round-trip test.

### Test review
The test agent found 10 findings. Two were real production bugs (fixed): (1) missing `iss`/`aud`
claims were misclassified as `IDTokenSignatureError` and triggered a spurious JWKS refetch -- fixed
by catching `jwt.MissingRequiredClaimError` before the generic `InvalidTokenError` handler; (2)
`userinfo_endpoint` was treated as required in discovery, blocking IdPs that omit it -- fixed by
making it optional (validated only if present, persisted as `None` when absent). Also fixed: the
discovery URL itself is now https-validated (#8), stale JWKS cache entries are evicted on read and
cleared on connection delete (#6), the dead `nonce` parameter was removed from `_decode_with_key`
(#9), and the `errors.py` types are re-exported from the package (#10). Coverage gaps were closed
with new tests for `iat`/`nbf`-future (#3), missing `iss`/`aud`/`exp`/`iat` claims (#4),
`decrypt_client_secret` round-trip (#5), and token-exchange/userinfo SSRF refusal (#7).

### Reconceptualisations
- **`userinfo_endpoint` is optional** -- per OIDC Discovery 1.0 it is RECOMMENDED, not REQUIRED.
  The discovery validator now treats it as optional (persisted `None` when absent). This corrects
  the Iteration 2 acceptance criterion's "four endpoints" wording; the other three
  (`authorization_endpoint`, `token_endpoint`, `jwks_uri`) remain required.
- **JWKS via `PyJWKSet`, not `PyJWKClient`** -- `PyJWKClient` performs its own unguarded `urllib`
  fetch and caches process-globally, bypassing the SSRF guard. The connector fetches through
  `build_safe_client()` and hands the parsed `PyJWKSet` to `jwt.decode`, selecting the key by `kid`
  explicitly. This deviates from the plan's "fetched via `PyJWKClient`" wording for SSRF safety.

### Decisions log
- **JWKS via `PyJWKSet`, not `PyJWKClient`** -- `PyJWKClient` does its own `urllib` fetch (bypassing
  the SSRF guard) and caches process-globally. Fetch through `build_safe_client()` and hand the
  parsed `PyJWKSet` to `jwt.decode`, selecting the key by `kid` explicitly (PyJWT's `PyJWKSet` isn't
  directly accepted as a `key`). -- **Context**: cross-cutting SSRF requirement. -- **Rationale**:
  keeps all outbound HTTP behind the guard.
- **Nonce checked explicitly** (PyJWT doesn't verify `nonce`), and `sub` presence enforced manually
  (PyJWT doesn't verify it by default). -- **Context**: PyJWT's `jwt.decode` does not cover these.
- **`decrypt_client_secret` added now** so the connector core is complete and the Iteration 3 flow
  has the reversible-secret accessor it needs. -- **Context**: the secret is encrypted (reversible)
  at rest, unlike OAuth2's hashed pattern.
- **No migration** was needed -- Iteration 2 is pure service code; the data model landed in
  Iteration 1.

---

## Iteration 3 -- Login and callback routes: PKCE, correlation, JIT, MFA gate
**Status**: Not started

The generic connector working end to end. After this iteration a connection created via the API
can log a user in.

### Acceptance criteria
- [ ] `GET /auth/oidc/{connection_id}/login`: generates `state`, `nonce`, and a PKCE
      `code_verifier` (S256 challenge), stores all three in the session, builds the authorize URL
      (including `hd` when `hosted_domain` is set), and redirects off-origin. Scopes
      `openid profile email` are always requested.
- [ ] `GET /auth/oidc/{connection_id}/callback`: validates `state`, exchanges the code with the
      `code_verifier`, validates the ID token (Iteration 2), correlates the user, and completes
      login. Single-use: the session's state/nonce/verifier are cleared on first use so a replayed
      callback fails.
- [ ] Redirects follow the CLAUDE.md policy: the authorize hop is a deliberate off-origin redirect
      (`safe_external_redirect()` against the tenant's registered hosts, or a `# redirect-ok:`
      waived `RedirectResponse`); every internal redirect goes through `safe_redirect()`.
- [ ] Correlation on `(idp_id, sub)` where `sub` is the claim named by `correlation_claim`:
      existing link authenticates that user; no link and `allow_email_linking` is true and the ID
      token carries `email_verified: true` and the email matches an existing user links them; no
      link and JIT enabled provisions; otherwise a clear rejection. `allow_email_linking=false`
      **never** attaches to an existing account.
- [ ] JIT provisioning mirrors the SAML flow: create user (password NULL), verified email, IdP link,
      base group, domain groups, mirror attributes, log `oidc_user_jit_provisioned`.
- [ ] **Platform MFA gate**: when the connection has `require_platform_mfa`, the callback stashes
      `pending_mfa_user_id` / `pending_mfa_method`, sends the email OTP when the method is email,
      and redirects to `/mfa/verify` instead of calling `complete_authenticated_login` -- exactly as
      `app/routers/saml/authentication.py:342` does. Otherwise it calls
      `complete_authenticated_login`.
- [ ] Inactivated users are rejected at the callback, matching the SAML behavior.
- [ ] Both routes are rate-limited via `ratelimit.prevent` (mirroring the ACS limits at
      `app/routers/saml/authentication.py:249`), keyed on IP and connection.
- [ ] Event types added (`event_types.py` + `.lock`): `oidc_login_started`, `oidc_login_completed`,
      `oidc_login_failed` (security tier), `oidc_user_jit_provisioned` (security tier),
      `user_oidc_idp_linked` (security tier).
- [ ] Tests with mocked IdP responses: state mismatch, missing verifier, replayed callback, PKCE
      round trip, each correlation branch (existing link, email-link allowed, email-link disallowed,
      email-link with `email_verified` false, JIT, JIT disabled), MFA-required branch reaching
      `/mfa/verify`, inactivated user, rate limiting, event emission.

### Layers affected
Service (auth, provisioning), Router, Tests.

### Guidance
- Session keys must be namespaced per connection (a user can start two logins), and cleared on
  completion and on failure.
- The MFA branch is the single easiest thing to get wrong in this feature. It is not optional
  polish: without it, enabling an OIDC IdP silently downgrades a tenant's MFA policy.

---

## Iteration 4 -- Admin UI
**Status**: Not started

The admin surface, built after the flow and the preset registry exist so the form is built once.

### Acceptance criteria
- [ ] List page, create/edit form with the vendor preset picker (Generic / Google / Entra)
      pre-filling authority/discovery URL, scopes, and correlation claim; detail tabs
      (details / danger; the claim-mapping tab arrives in Iteration 5).
- [ ] The connection detail page displays the callback URL to paste into the IdP console, with a
      copy-to-clipboard control (`WeftUtils`).
- [ ] Preset-conditional fields: Entra asks for a tenant ID, Google offers the hosted domain.
      `require_platform_mfa`, `jit_provisioning`, and `allow_email_linking` are exposed as toggles,
      with `allow_email_linking` carrying an explanatory warning about its account-linking effect.
- [ ] Test-connection action: runs real discovery (Iteration 2) and reports success/failure with
      the discovered endpoints. Not a placeholder.
- [ ] All pages registered in `app/pages.py` under a new SUPER_ADMIN section
      (`/admin/settings/oidc-identity-providers`) with `docs_path` set.
- [ ] `make build-css` run after the templates land.
- [ ] Tests: router happy paths, authz (non-super-admin refused), form validation, secret never
      rendered.

### Layers affected
Router (admin), Templates, Tests.

### Guidance
- Do not reuse the SAML templates -- different fields and tabs. Follow their shape, not their markup.
- No inline `onclick`/`onsubmit` (CSP); server values go in a `page-data` JSON block.

---

## Iteration 5 -- Claim mapping + attribute mirroring
**Status**: Not started

Configurable claim-to-attribute mapping and the OIDC parallel of the mirroring infrastructure.

### Acceptance criteria
- [ ] Migration adds `user_oidc_idp_attributes` (parallel to `user_idp_attributes`, FK to
      `oidc_idp_connections`) + database module.
- [ ] `apply_oidc_idp_attributes` mirrors `apply_idp_attributes` but validates `idp_id` against
      `oidc_idp_connections` and writes the OIDC snapshot table: replace the snapshot atomically,
      upsert canonical `user_attributes` only for keys the tenant has `enabled AND mirror_from_idp`,
      emit `user_profile_updated` with `cause=idp_mirror`.
- [ ] Mirror is soft-fail (a mirror bug must not break login) -- mirror the
      `_apply_idp_attributes_safe` wrapper pattern.
- [ ] Claim-mapping UI tab + `/api/v1` endpoint for reading and updating `claim_mapping`, using the
      14-attribute registry in `app/constants/user_attributes.py`. Unknown attribute keys are
      dropped.
- [ ] Disconnect scrub wired up: deleting an OIDC connection calls `scrub_canonical_matches_mirror`
      for its linked users, matching `app/services/saml/providers.py:388`.
- [ ] Tests: mapping translation, mirror write (canonical + snapshot), tenant-config gating, soft-
      fail, scrub-on-delete.

### Layers affected
Database (migration + module), Service, API, Router (admin), Templates, Tests.

### Guidance
- The `user_oidc_idp_attributes` snapshot is read-only for admins; only the mirror writer touches it.

---

## Iteration 6 -- Privileged domain routing
**Status**: Not started

OIDC IdPs become binding targets, and the login flow routes to them.

### Acceptance criteria
- [ ] Migration adds `oidc_idp_domain_bindings` (parallel to `saml_idp_domain_bindings`):
      `(tenant_id, domain_id, idp_id)`, unique `(tenant_id, domain_id)`, FKs to
      `tenant_privileged_domains` and `oidc_idp_connections`, RLS strict. A domain binds to at most
      one IdP across **both** protocols -- enforce that in the service, since the DB constraint
      cannot span two tables.
- [ ] Database + service bind/unbind/list mirroring `app/services/saml/domains.py`, including its
      `scrub_canonical_matches_mirror` call on unbind (`domains.py:517`), plus `/api/v1` endpoints.
- [ ] Event types: `oidc_domain_bound`, `oidc_domain_unbound`, `oidc_domain_rebound`,
      `user_oidc_idp_assigned` (mirroring the SAML set).
- [ ] Routing: `determine_auth_route` gains OIDC route types (`idp_oidc`, `idp_oidc_jit`,
      `idp_oidc_disabled`) resolved from `oidc_idp_user_links`, OIDC domain bindings, and the
      OIDC default connection. `app/routers/auth/_helpers.py` redirects those to
      `/auth/oidc/{connection_id}/login` in **both** `_route_after_email_verification` and
      `_route_without_verification` (the latter must keep its no-disclosure behavior).
- [ ] SAML and OIDC identity are treated as mutually exclusive per user: a user with
      `saml_idp_id` set and a user with an OIDC link cannot both resolve, and the resolution order
      is explicit and tested.
- [ ] Privileged-domains admin UI shows both protocols as binding targets (protocol column or
      grouped select).
- [ ] Tests: every routing branch (linked OIDC user, domain-bound JIT, default JIT, disabled
      connection, both-protocols conflict), binding CRUD + RLS, login-flow redirect.

### Layers affected
Database (migration + module), Service (routing, domains), API, Router (auth helpers, admin),
Templates, Tests.

### Guidance
- `determine_auth_route` and `AuthRouteResult` currently live in `app/services/saml/routing.py` and
  `app/schemas/saml.py`. Adding OIDC route types to SAML-named modules is a compliance smell.
  **Decision for this iteration**: move both to protocol-neutral homes
  (`app/services/auth_routing.py`, `app/schemas/auth_routing.py`) with re-exports from the SAML
  modules for backwards compatibility, and update the call sites. If the dev agent finds the move
  materially larger than expected, leave them in place and record the deviation in the decisions
  log rather than half-moving them.

---

## Iteration 7 -- Preset hardening + E2E
**Status**: Not started

Per-preset behavior verified against recorded fixtures, and a real end-to-end login flow.

### Acceptance criteria
- [ ] Recorded fixtures per preset under `tests/fixtures/oidc/<preset>/` (discovery JSON, signed ID
      token JWTs, userinfo responses); tests cover authorize-URL shape (including Google `hd`),
      discovery, ID token validation, and correlation-subject selection (`sub` vs `oid`).
- [ ] Google preset end to end against fixtures: hosted-domain parameter present when configured.
- [ ] Entra preset end to end against fixtures: authority composed from `entra_tenant_id`,
      correlation on `oid`.
- [ ] E2E test in `tests/e2e/` driving a real browser through an upstream OIDC login: WeftID's own
      downstream OP as the upstream IdP (loopback, following the pattern in
      `tests/e2e/test_scim_loopback_e2e.py`), covering login, JIT provisioning, and a second login
      correlating on `sub`.
- [ ] `dev/seed_dev.py` seeds an OIDC connection for the Meridian Health fixture so the flow is
      reachable by hand.

### Layers affected
Service (presets), Tests (unit + E2E), Dev fixtures.

### Guidance
- The loopback approach (WeftID's OP as its own upstream) avoids a new container and exercises both
  protocol directions in one test. If it proves circular in a way that breaks tenant isolation, the
  fallback is the Authentik instance from `dev/scim-testbed.sh`, which is already an OIDC OP and
  already reachable via `host.docker.internal` on the SSRF dev allowlist. Decide early in the
  iteration and record it.
- No live external API calls in any test.

---

## Iteration 8 -- Docs, release prep, final review
**Status**: Not started

### Acceptance criteria
- [ ] `docs/admin-guide/identity-providers/oidc-setup.md` covering the generic connector (Keycloak,
      Auth0, custom IdP walkthroughs) + per-preset subpages (`oidc-google.md`, `oidc-entra.md`),
      each documenting the callback URL the admin must register.
- [ ] Glossary entries: OIDC, OpenID Connect, PKCE, authorization code flow with PKCE, OIDC
      discovery, JWKS, ID token, userinfo endpoint (cross-link from the existing OAuth2 entry).
- [ ] Privileged-domains docs updated for OIDC binding targets; the `allow_email_linking` security
      trade-off documented explicitly.
- [ ] `CHANGELOG.md` entry and a minor version bump in `pyproject.toml` (additive feature per
      `docs/VERSIONING.md`).
- [ ] Final review pass: test (+e2e), security, compliance, tech-writer agents over the full branch
      diff; findings triaged and resolved; `make quality-all` green.
- [ ] Backlog split per the "Backlog closure" note above -- do not archive the item wholesale.

### Layers affected
Docs, Tests.

### Guidance
- Docs live under `docs/admin-guide/identity-providers/` (upstream-consumer direction), unlike the
  downstream OP docs under `integrations/`.
- The security agent should be pointed explicitly at the SSRF surface, the MFA gate, and the
  email-linking path.

---

## Future iterations
- **Group claim handling** (deferred follow-on backlog item): per-preset group claim sources --
  Entra Graph GUID-to-name mapping, GitHub orgs/teams API, Okta `groups` claim, Google custom-claim
  opt-in. The connection's `group_claim_source` column is reserved for this.
- **GitHub + Okta presets** (deferred): thin layers over the preset registry.
- **Social Sign-In Providers** (Phase 2 backlog item): Apple, Facebook, Discord, LinkedIn, etc.
  with per-provider adapters for non-standard OIDC.

---

## Plan revision log

- **2026-08-30 -- plan review.** Re-split 6 iterations into 8; settled the full
  `oidc_idp_connections` column set in Iteration 1 (previously it omitted `require_platform_mfa`,
  `correlation_claim`, `hosted_domain`, `entra_tenant_id`, `group_claim_source`, discovery-cache
  columns, and `allow_email_linking`, each of which a later iteration required, forcing a second
  migration and a form rewrite). Added three cross-cutting requirements the original plan omitted:
  the SSRF-hardened HTTP client, the platform-MFA gate on the callback, and the `/api/v1` surface.
  Replaced the undecided `idp_slug` with the connection UUID, matching SAML. Made email-based
  account linking opt-in and gated on `email_verified`. Moved the admin UI after the connector so
  the form is built once, and made test-connection real rather than a placeholder. Gave E2E its own
  iteration with a named strategy. Added the missing domain-binding and enable/disable event types,
  the disconnect scrub, and the `determine_auth_route` relocation decision. Flagged that the backlog
  item cannot be archived as Complete.

---

## Final review
[Populated after Step 8.]
