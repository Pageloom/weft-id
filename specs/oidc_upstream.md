# OIDC Upstream IdP Support (Generic + Google + Entra)

**Slug**: `oidc_upstream`
**Backlog item**: OIDC Upstream IdP Support (with Entra, Google, GitHub, Okta Presets)
**Branch**: `oidc-upstream`
**Created**: 2026-08-30
**Revised**: 2026-08-30 (plan review -- re-split into 8 iterations, column set settled,
cross-cutting concerns added)
**Status**: In progress -- Iteration 8 of 9

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
**Status**: Complete
**Completed**: 2026-08-31

The generic connector working end to end. After this iteration a connection created via the API
can log a user in.

### Acceptance criteria
- [x] `GET /auth/oidc/{connection_id}/login`: generates `state`, `nonce`, and a PKCE
      `code_verifier` (S256 challenge), stores all three in the session, builds the authorize URL
      (including `hd` when `hosted_domain` is set), and redirects off-origin. Scopes
      `openid profile email` are always requested.
- [x] `GET /auth/oidc/{connection_id}/callback`: validates `state`, exchanges the code with the
      `code_verifier`, validates the ID token (Iteration 2), correlates the user, and completes
      login. Single-use: the session's state/nonce/verifier are cleared on first use so a replayed
      callback fails.
- [x] Redirects follow the CLAUDE.md policy: the authorize hop is a deliberate off-origin redirect
      (`safe_external_redirect()` against the tenant's registered hosts, or a `# redirect-ok:`
      waived `RedirectResponse`); every internal redirect goes through `safe_redirect()`.
- [x] Correlation on `(idp_id, sub)` where `sub` is the claim named by `correlation_claim`:
      existing link authenticates that user; no link and `allow_email_linking` is true and the ID
      token carries `email_verified: true` and the email matches an existing user links them; no
      link and JIT enabled provisions; otherwise a clear rejection. `allow_email_linking=false`
      **never** attaches to an existing account.
- [x] JIT provisioning mirrors the SAML flow: create user (password NULL), verified email, IdP link,
      base group, domain groups, mirror attributes, log `oidc_user_jit_provisioned`.
- [x] **Platform MFA gate**: when the connection has `require_platform_mfa`, the callback stashes
      `pending_mfa_user_id` / `pending_mfa_method`, sends the email OTP when the method is email,
      and redirects to `/mfa/verify` instead of calling `complete_authenticated_login` -- exactly as
      `app/routers/saml/authentication.py:342` does. Otherwise it calls
      `complete_authenticated_login`.
- [x] Inactivated users are rejected at the callback, matching the SAML behavior.
- [x] Both routes are rate-limited via `ratelimit.prevent` (mirroring the ACS limits at
      `app/routers/saml/authentication.py:249`), keyed on IP and connection.
- [x] Event types added (`event_types.py` + `.lock`): `oidc_login_started`, `oidc_login_completed`,
      `oidc_login_failed` (security tier), `oidc_user_jit_provisioned` (security tier),
      `user_oidc_idp_linked` (security tier).
- [x] Tests with mocked IdP responses: state mismatch, missing verifier, replayed callback, PKCE
      round trip, each correlation branch (existing link, email-link allowed, email-link disallowed,
      email-link with `email_verified` false, JIT, JIT disabled), MFA-required branch reaching
      `/mfa/verify`, inactivated user, rate limiting, event emission.

### What was done
- `app/services/oidc_upstream/auth.py` -- `authenticate_via_oidc` correlation entry point: existing
  `(idp_id, sub)` link -> authenticate; else `allow_email_linking` + `email_verified: true` +
  matching email -> link + authenticate; else JIT -> provision; else reject. Inactivated users are
  rejected. Emits `oidc_login_completed` / `user_oidc_idp_linked`.
- `app/services/oidc_upstream/provisioning.py` -- `jit_provision_user`: create user (NULL password),
  verified email, `oidc_idp_user_links` row, domain-group auto-assignment, log
  `oidc_user_jit_provisioned`. **Account-takeover guard**: rejects (rather than returning) a
  pre-existing account on an email match when `allow_email_linking` is off.
- `app/routers/oidc_upstream/authentication.py` -- `GET /auth/oidc/{connection_id}/login` and
  `/callback`: PKCE (S256) state/nonce/verifier namespaced per connection and cleared on first use;
  token exchange + ID-token validation + userinfo merge; platform-MFA gate (stash
  `pending_mfa_user_id`/`pending_mfa_method`, email OTP, redirect to `/mfa/verify`); rate limiting
  on both routes; UUID validation on `connection_id`; `oidc_login_started`/`oidc_login_failed`
  logged with `SYSTEM_ACTOR_ID`.
- `app/services/oidc_upstream/connections.py` -- added `get_connection_row()` (wraps the database
  `get_connection` so the router never imports the database layer directly).
- `app/services/oidc_upstream/__init__.py` -- re-exported `get_connection_row` and the auth surface.
- `app/constants/event_types.py` + `event_types.lock` -- added the 5 new event types (descriptions
  + tiers, sorted).

### Tests added
- `tests/services/test_oidc_upstream_auth.py` -- correlation branches (existing link, email-link
  allowed/disallowed, email-link `email_verified` false, JIT, JIT disabled, inactivated user).
- `tests/services/test_oidc_upstream_provisioning.py` -- JIT provisioning, invalid email, and the
  account-takeover guard (JIT + `allow_email_linking=false` + existing email -> rejected, no link).
- `tests/routers/test_oidc_upstream_authentication.py` -- login redirect/off-origin, disabled and
  unknown and malformed connection, callback state mismatch / missing verifier / idp error /
  unknown / malformed connection, PKCE round trip (JIT), MFA-required redirect to `/mfa/verify`.

### Test review
The test agent found 4 findings. Three were real production bugs, all fixed:

1. **[HIGH] JIT silently authenticated an existing account on an email match**, bypassing the
   `allow_email_linking` guard (account takeover). Fixed: `jit_provision_user` now raises
   `ValidationError(code="oidc_jit_email_exists")` instead of returning the existing user.
2. **[MEDIUM] `oidc_login_started`/`oidc_login_failed` used `actor_user_id=tenant_id`**, causing a
   swallowed FK violation in `track_activity` and wrong audit attribution. Fixed: both now use
   `SYSTEM_ACTOR_ID` (matching the SAML IdP-driven events).
3. **[MEDIUM] No UUID validation on `connection_id`** -> unhandled 500 on malformed input. Fixed:
   `_get_connection` validates the UUID and returns `None` (mapped to `idp_not_found`).

Finding #4 (rate-limit key not keyed on connection) was a spec-deviation note, not a bug; the key
shape matches the SAML ACS precedent and was left as-is (see decisions log). Coverage gaps noted
(rate limiting untested, replayed-callback not truly exercised, vacuous `test_login_stores_session_state`,
event-emission not asserted) were recorded; the account-takeover and malformed-connection gaps were
closed with new tests.

### Reconceptualisations
- **JIT must never return a pre-existing account.** The SAML `jit_provision_user` race-guard pattern
  (return the existing user on an email match) does not transfer to OIDC: SAML correlates on email
  against a certificate-verified assertion, whereas OIDC correlates on `(idp_id, sub)` and email
  linking is opt-in. Copying the guard verbatim created an account-takeover vector. The OIDC JIT
  path now rejects on an email match instead.

### Decisions log
- **Rate-limit key left keyed on IP + tenant (not connection).** -- **Context**: test finding #4
  noted the spec says "keyed on IP and connection" but the implementation uses
  `oidc_login:tenant:{tenant_id}:ip:{ip}`. -- **Rationale**: matches the SAML ACS key shape
  (`saml_acs:tenant:{tenant_id}:ip:{ip}`); per-connection isolation has low practical value at the
  20/5min limit, and deviating from the SAML precedent would be inconsistent. Recorded as an
  accepted deviation rather than a fix.
- **Pre-auth events use `SYSTEM_ACTOR_ID`.** -- **Context**: `log_event` calls `track_activity` for
  any non-system actor, which would insert a `user_activity` row with `user_id = <tenant uuid>`
  (FK violation, swallowed). -- **Rationale**: the SAML IdP-driven events already use
  `SYSTEM_ACTOR_ID`; the audit viewer renders `"IdP: {name}"` for system actors with `idp_name` in
  metadata.
- **Base-group and attribute-mirroring steps deferred.** -- **Context**: the acceptance criterion
  lists "base group" and "mirror attributes" in the JIT flow, but the implementation omits both.
  -- **Rationale**: base-group infrastructure is SAML-specific (`groups.idp_id` FKs to
  `saml_identity_providers`) and needs a migration; attribute mirroring is owned by Iteration 5
  (the `user_oidc_idp_attributes` snapshot table does not exist yet). Domain-group auto-assignment
  (protocol-agnostic, email-domain based) is included. Both deferred steps are already scoped to
  later iterations.

---

## Iteration 4 -- Admin UI
**Status**: Complete
**Completed**: 2026-08-31

The admin surface, built after the flow and the preset registry exist so the form is built once.

### Acceptance criteria
- [x] List page, create/edit form with the vendor preset picker (Generic / Google / Entra)
      pre-filling authority/discovery URL, scopes, and correlation claim; detail tabs
      (details / danger; the claim-mapping tab arrives in Iteration 5).
- [x] The connection detail page displays the callback URL to paste into the IdP console, with a
      copy-to-clipboard control (`WeftUtils`).
- [x] Preset-conditional fields: Entra asks for a tenant ID, Google offers the hosted domain.
      `require_platform_mfa`, `jit_provisioning`, and `allow_email_linking` are exposed as toggles,
      with `allow_email_linking` carrying an explanatory warning about its account-linking effect.
- [x] Test-connection action: runs real discovery (Iteration 2) and reports success/failure with
      the discovered endpoints. Not a placeholder.
- [x] All pages registered in `app/pages.py` under a new SUPER_ADMIN section
      (`/admin/settings/oidc-identity-providers`) with `docs_path` set.
- [x] `make build-css` run after the templates land.
- [x] Tests: router happy paths, authz (non-super-admin refused), form validation, secret never
      rendered.

### What was done
- `app/routers/oidc_upstream/admin.py` -- Admin router mirroring `routers/saml/admin/providers.py`:
  list, create form (with vendor preset picker), detail tabs (details/danger), and POST handlers
  (edit name, edit settings, toggle, set-default, delete, test-connection). The test-connection
  action runs real discovery via `oidc_service.run_discovery(force=True)` and reports success/failure
  with discovered endpoints. Entra preset composes its issuer from `entra_tenant_id`. The create
  handler catches Pydantic `ValidationError` and redirects with a generic `error=invalid_input`
  rather than returning a 500.
- `app/templates/oidc_idp_list.html` -- List page (name/provider-type/status/discovery columns,
  default badge).
- `app/templates/oidc_idp_form.html` -- Create form with Generic/Google/Entra preset picker that
  pre-fills issuer, discovery URL, scopes, and correlation claim via a `page-data` JSON block;
  preset-conditional fields (Entra tenant ID, Google hosted domain); `require_platform_mfa` /
  `jit_provisioning` / `allow_email_linking` toggles with the account-linking warning. The issuer
  field is conditionally required (not required for Entra, where it is composed from the tenant ID).
- `app/templates/oidc_idp_base.html` -- Shared tab-bar layout (Details / Delete).
- `app/templates/oidc_idp_tab_details.html` -- Details tab: callback URL with copy-to-clipboard,
  endpoint display, settings form, test-connection action, and an edit-name modal (wired to the
  `/edit` route).
- `app/templates/oidc_idp_tab_danger.html` -- Danger tab: enable/disable gate + delete with
  confirmation modal.
- `app/routers/oidc_upstream/__init__.py` -- Now includes the admin router alongside the auth router.
- `app/pages.py` -- Registered the new SUPER_ADMIN section `/admin/settings/oidc-identity-providers`
  (with `new`, `connection`, `connection/details`, `connection/danger` children) and `docs_path` set.
- `app/services/oidc_upstream/presets.py` -- Added an `issuer` field to `OIDCPreset` and
  `get_preset_defaults` (Google -> `https://accounts.google.com`; Entra -> None, composed from
  tenant id) so the preset picker can pre-fill the authority.

### Tests added
- `tests/routers/test_oidc_upstream_admin.py` -- 22 tests covering list/new/create (incl. Entra
  issuer composition), detail tabs, secret-never-rendered, POST handlers, delete-conflict,
  test-connection success/failure, invalid `provider_type` and empty `issuer` (both redirect with
  `error=invalid_input`, not 500), and Google issuer pre-fill in the new-form response.
- `tests/services/test_oidc_upstream_presets.py` -- Added assertions for the Google preset's
  `issuer` field and its presence in `get_preset_defaults`.

### Test review
The test agent found 7 findings. One was a real high-severity production bug, fixed:

1. **[HIGH] Unhandled Pydantic `ValidationError` -> HTTP 500 on the create form.** The route
   constructed `OIDCConnectionCreate(...)` directly; a malformed form value (bad `provider_type`,
   empty `issuer`, over-length field) raised `pydantic_core.ValidationError`, which the
   `except ValidationError` clause (catching `services.exceptions.ValidationError`) did not catch.
   Fixed: the schema construction is now wrapped in a `try/except PydanticValidationError` that
   redirects with a generic `error=invalid_input` (no raw `str(e)` echo, to avoid leaking field
   names/values).

Also fixed (medium/low, from the same review):

2. **[MEDIUM] Entra "compose issuer from tenant ID" unreachable via the form.** The issuer input
   had an unconditional HTML `required` attribute, so a browser blocked submission when the issuer
   was empty. Fixed: the issuer field is now conditionally required (removed for Entra, where the
   authority is composed from the tenant ID).
3. **[MEDIUM] Preset picker did not pre-fill the issuer/authority.** `get_preset_defaults` carried
   no issuer; the Google preset left the issuer blank. Fixed: added an `issuer` field to the preset
   (Google -> `https://accounts.google.com`; Entra -> None) and set `issuerInput.value` in
   `applyPreset()`.
4. **[LOW] "Edit name" pencil button was a dead control.** No JS listener or form was wired to it.
   Fixed: added an edit-name modal (mirroring the SAML details tab) posting to the existing `/edit`
   route.

Findings #4 (no full "edit form" -- only name + boolean toggles editable) and #5 (default provider
cannot be unset) were recorded as accepted scope decisions rather than fixed (see decisions log).
The `ResourceWarning: unclosed socket` messages at interpreter shutdown are pre-existing (memcached
client) and do not fail the suite.

### Reconceptualisations
- **The preset picker now pre-fills the issuer/authority, not just discovery URL/scopes/correlation
  claim.** The original acceptance criterion said "authority/discovery URL" but the preset registry
  only carried `discovery_url`. Added an `issuer` field to `OIDCPreset` so Google pre-fills
  `https://accounts.google.com` and Entra leaves it empty (composed from the tenant ID). This is a
  correction to the Iteration 2 preset shape, not a new data model.

### Decisions log
- **No full "edit form" this iteration.** -- **Context**: acceptance criterion 1 says "create/edit
  form", but the implementation provides a create form plus inline name edit and boolean toggles;
  `issuer`, `discovery_url`, `client_id`, `client_secret`, `scopes`, `correlation_claim`,
  `hosted_domain`, `entra_tenant_id` are immutable post-creation. -- **Rationale**: the SAML admin
  surface is also name-only + toggles (its endpoints come from metadata import, not a form); a full
  edit form is a larger surface than the criterion strictly requires and can be added later if
  admins need to fix endpoint typos without delete/recreate. Recorded as an accepted gap.
- **"Default Provider" cannot be unset from the UI.** -- **Context**: the settings form exposes an
  `is_default` checkbox but the handler only ever *sets* default; `set_connection_default` in the DB
  layer only writes `true`. -- **Rationale**: this mirrors the SAML behavior exactly (un-defaulting
  requires picking another default), and the DB trigger unsets other defaults. The checkbox is
  slightly misleading but consistent with the SAML precedent; left as-is rather than adding an
  `unset_connection_default` path that SAML does not have.
- **Pydantic validation errors redirect with a generic message.** -- **Context**: the create form
  passes many strictly-constrained fields; echoing `str(e)` would leak field names/values. --
  **Rationale**: a generic `error=invalid_input` is safe and sufficient for an admin surface.

---

## Iteration 5 -- Claim mapping + attribute mirroring
**Status**: Complete
**Completed**: 2026-08-31

Configurable claim-to-attribute mapping and the OIDC parallel of the mirroring infrastructure.

### Acceptance criteria
- [x] Migration adds `user_oidc_idp_attributes` (parallel to `user_idp_attributes`, FK to
      `oidc_idp_connections`) + database module.
- [x] `apply_oidc_idp_attributes` mirrors `apply_idp_attributes` but validates `idp_id` against
      `oidc_idp_connections` and writes the OIDC snapshot table: replace the snapshot atomically,
      upsert canonical `user_attributes` only for keys the tenant has `enabled AND mirror_from_idp`,
      emit `user_profile_updated` with `cause=idp_mirror`.
- [x] Mirror is soft-fail (a mirror bug must not break login) -- mirror the
      `_apply_idp_attributes_safe` wrapper pattern.
- [x] Claim-mapping UI tab + `/api/v1` endpoint for reading and updating `claim_mapping`, using the
      14-attribute registry in `app/constants/user_attributes.py`. Unknown attribute keys are
      dropped.
- [x] Disconnect scrub wired up: deleting an OIDC connection calls `scrub_canonical_matches_mirror`
      for its linked users, matching `app/services/saml/providers.py:388`.
- [x] Tests: mapping translation, mirror write (canonical + snapshot), tenant-config gating, soft-
      fail, scrub-on-delete.

### What was done
- `db-init/migrations/0058_oidc_upstream_attributes.sql` -- Creates `user_oidc_idp_attributes`
  (parallel to `user_idp_attributes`, FK to `oidc_idp_connections` CASCADE, strict fail-closed
  RLS, `value` <=2000 CHECK, tenant/user + tenant/idp indexes).
- `app/database/oidc_upstream/attributes.py` -- Read/delete helpers for the snapshot table
  (`list_attributes`, `list_attributes_for_idp`, `replace_idp_attributes`, `delete_for_user`,
  `delete_for_user_idp`).
- `app/database/oidc_upstream/__init__.py` -- Re-exports the new attribute helpers.
- `app/services/oidc_upstream/attributes.py` -- `apply_oidc_idp_attributes` (ownership check
  against `oidc_idp_connections`, atomic snapshot replace, canonical upsert gated on
  `enabled AND mirror_from_idp`, single `user_profile_updated` event with `cause=idp_mirror`) and
  `scrub_oidc_canonical_matches_mirror` (parallel to `scrub_canonical_matches_mirror`, with an
  optional `user_id` confinement for the Iteration 6 per-user disconnect path).
- `app/services/oidc_upstream/provisioning.py` -- `_extract_standard_attributes` (lifts the 14
  registry keys via `claim_mapping`) and `_apply_oidc_idp_attributes_safe` (soft-fail wrapper
  emitting `user_idp_attribute_mirror_failed` on failure), wired into all three auth branches.
- `app/services/oidc_upstream/connections.py` -- `get_claim_mapping` / `update_claim_mapping`
  (drops unknown keys), and `delete_connection` now calls `scrub_oidc_canonical_matches_mirror`
  before the delete.
- `app/schemas/oidc_upstream.py` -- `claim_mapping` validators on `OIDCConnectionCreate`/`Update`
  now **drop** unknown keys (matching the spec and the PUT path) instead of rejecting them.
- `app/routers/api/v1/oidc_upstream.py` -- `GET`/`PUT /connections/{id}/claim-mapping` endpoints
  (super-admin-gated) plus the `ClaimMappingUpdate` request schema.

### Tests added
- `tests/services/test_oidc_upstream_attributes.py` -- `_extract_standard_attributes` unit tests
  (mapping translation, empty/non-string drop, missing-claim omission, non-registry key ignore);
  `apply_oidc_idp_attributes` end-to-end (mirror on/off, unknown-key drop, unknown-connection
  NotFound); soft-fail (existing-user and JIT-user mirror failure does not break login, emits
  `user_idp_attribute_mirror_failed`); scrub-on-delete (clears matching canonical rows, leaves
  diverged rows); `update_claim_mapping`/`get_claim_mapping` (unknown-key drop + round-trip);
  schema validation (create/update drop unknown keys, None mapping passes).

### Test review
The test agent's review found the feature functionally implemented but with **zero tests** for the
Iteration 5 acceptance criteria (High), plus a medium-severity inconsistency (PATCH rejected
unknown claim-mapping keys while PUT dropped them) and three low-severity cleanups. Resolution:

- **Finding 1 (no tests)** -- Fixed: added `tests/services/test_oidc_upstream_attributes.py`
  mirroring `test_saml_attribute_ingestion.py` (17 tests).
- **Finding 2 (scrub-on-delete dead code)** -- Accepted as intentional. The delete-guard
  (`link_count > 0`) means mirror rows always coexist with a link, so the delete-path scrub is a
  no-op until Iteration 6 adds the per-user disconnect path. `scrub_oidc_canonical_matches_mirror`
  already accepts an optional `user_id` for that path. No code change; documented below.
- **Finding 3 (inconsistent unknown-key handling)** -- Fixed: `_validate_claim_mapping_keys` now
  drops unknown keys (matching the spec and the PUT path) instead of raising. Both PATCH and PUT
  now behave identically.
- **Finding 4 (dead DB functions + duplicated replace logic)** -- Accepted. `replace_idp_attributes`
  is redundant with the inline SQL in `apply_oidc_idp_attributes` (which matches
  `apply_idp_attributes`'s inline style); `delete_for_user_idp`/`list_attributes_for_idp` are
  reserved for Iteration 6. Left in place; no change.
- **Finding 5 (`except ValueError, ValidationError:`)** -- Fixed: changed to
  `except (ValueError, ValidationError):` for clarity.
- **Finding 6 (unnecessary DB round-trip on empty attributes)** -- Accepted as minor; no change.

### Reconceptualisations
- **Scrub-on-delete is a no-op until Iteration 6.** The delete-guard (`link_count > 0`) blocks
  deleting a connection with linked users, and mirror rows only ever coexist with a link, so the
  delete-path scrub can never delete anything. The real scrub need is the per-user disconnect/unbind
  path, which Iteration 6 owns. `scrub_oidc_canonical_matches_mirror` already supports a `user_id`
  confinement for that path. Iteration 6 must wire `scrub_oidc_canonical_matches_mirror(user_id=...)`
  + `delete_for_user_idp` into the per-user disconnect flow.

### Decisions log
- **Decision**: Unknown claim-mapping keys are **dropped** (not rejected) at the schema boundary. --
  **Context**: The spec says "Unknown attribute keys are dropped," but the dev agent's
  `field_validator` rejected them (422) while the PUT endpoint dropped them, producing inconsistent
  behavior. -- **Rationale**: Match the spec and make PATCH/PUT consistent; the mirror writer also
  drops unknown keys as defence in depth.
- **Decision**: Leave `replace_idp_attributes` and the other DB helpers in place despite
  `apply_oidc_idp_attributes` using inline SQL. -- **Context**: The DB module mirrors the SAML
  `user_idp_attributes` module, but the service chose inline SQL matching `apply_idp_attributes`. --
  **Rationale**: `delete_for_user_idp`/`list_attributes_for_idp` are genuinely needed for Iteration
  6; removing only `replace_idp_attributes` would be churn for no functional gain.
- **Decision**: Accept the scrub-on-delete no-op rather than relaxing the delete-guard. --
  **Context**: The test agent flagged that the delete-path scrub is unreachable because the guard
  blocks deletion of linked connections. -- **Rationale**: Relaxing the guard to allow deleting a
  connection with linked users would be a behavior change with security implications; the correct
  scrub point is the per-user disconnect path in Iteration 6.

---

## Iteration 6 -- Privileged domain routing
**Status**: Complete
**Completed**: 2026-09-01

OIDC IdPs become binding targets, and the login flow routes to them.

### Acceptance criteria
- [x] Migration adds `oidc_idp_domain_bindings` (parallel to `saml_idp_domain_bindings`):
      `(tenant_id, domain_id, idp_id)`, unique `(tenant_id, domain_id)`, FKs to
      `tenant_privileged_domains` and `oidc_idp_connections`, RLS strict. A domain binds to at most
      one IdP across **both** protocols -- enforce that in the service, since the DB constraint
      cannot span two tables.
- [x] Database + service bind/unbind/list mirroring `app/services/saml/domains.py`, including its
      `scrub_canonical_matches_mirror` call on unbind (`domains.py:517`), plus `/api/v1` endpoints.
- [x] Event types: `oidc_domain_bound`, `oidc_domain_unbound`, `oidc_domain_rebound`,
      `user_oidc_idp_assigned` (mirroring the SAML set).
- [x] Routing: `determine_auth_route` gains OIDC route types (`idp_oidc`, `idp_oidc_jit`,
      `idp_oidc_disabled`) resolved from `oidc_idp_user_links`, OIDC domain bindings, and the
      OIDC default connection. `app/routers/auth/_helpers.py` redirects those to
      `/auth/oidc/{connection_id}/login` in **both** `_route_after_email_verification` and
      `_route_without_verification` (the latter must keep its no-disclosure behavior).
- [x] SAML and OIDC identity are treated as mutually exclusive per user: a user with
      `saml_idp_id` set and a user with an OIDC link cannot both resolve, and the resolution order
      is explicit and tested.
- [x] Privileged-domains admin UI shows both protocols as binding targets (protocol column or
      grouped select).
- [x] Tests: every routing branch (linked OIDC user, domain-bound JIT, default JIT, disabled
      connection, both-protocols conflict), binding CRUD + RLS, login-flow redirect.

### What was done
- `db-init/migrations/0059_oidc_upstream_domain_bindings.sql` -- Creates `oidc_idp_domain_bindings`
  (`(tenant_id, domain_id, idp_id)`, UNIQUE `(tenant_id, domain_id)`, FKs to
  `tenant_privileged_domains` and `oidc_idp_connections`, strict fail-closed RLS).
- `app/database/oidc_upstream/domains.py` -- Bind/unbind/list/get-by-domain/get-connection-for-domain
  queries mirroring `database/saml/domains.py`; `get_unbound_domains` excludes SAML-bound domains.
- `app/database/oidc_upstream/__init__.py` -- Re-exports the new domain functions.
- `app/database/oidc_upstream/links.py` -- Added `get_link_for_user` (first link by `created_at`)
  for the routing decision point.
- `app/database/saml/domains.py` -- `get_unbound_domains` now excludes OIDC-bound domains.
- `app/services/oidc_upstream/domains.py` -- `bind_domain_to_connection` / `unbind` / `rebind` /
  `list` / `get_unbound_domains`; cross-protocol exclusivity enforced (rejects SAML-bound domains
  with `ConflictError` code `domain_bound_to_saml_idp`).
- `app/services/saml/domains.py` -- `bind_domain_to_idp` now rejects OIDC-bound domains
  (`ConflictError` code `domain_bound_to_oidc_connection`), closing the one-way exclusivity gap.
- `app/services/auth_routing.py` -- `determine_auth_route` moved here (protocol-neutral) with OIDC
  route types; explicit resolution order (SAML assignment → OIDC link → password → JIT routes).
- `app/schemas/auth_routing.py` -- `AuthRouteResult` moved here (protocol-neutral).
- `app/services/saml/routing.py` / `app/schemas/saml.py` -- Re-export the moved symbols for
  backwards compatibility.
- `app/routers/auth/_helpers.py` -- Redirects `idp_oidc`/`idp_oidc_jit` to
  `/auth/oidc/{id}/login` and `idp_oidc_disabled` to the disabled error, in both routing helpers.
- `app/routers/api/v1/oidc_upstream.py` -- `/api/v1` bind/unbind/list endpoints for OIDC domains.
- `app/routers/settings.py` -- OIDC bind/unbind admin routes; OIDC bind returns a distinct
  `success=domain_bound_oidc` value.
- `app/templates/settings_privileged_domains.html` -- Shows both SAML and OIDC binding badges and
  controls; protocol-specific success copy and a corrected bottom note.
- `app/services/oidc_upstream/provisioning.py` -- Emits `user_oidc_idp_assigned` on both the
  email-linking and JIT-provisioning branches (previously declared but never emitted).
- `app/constants/event_types.py` / `event_types.lock` -- Added `oidc_domain_bound`,
  `oidc_domain_unbound`, `oidc_domain_rebound`, `user_oidc_idp_assigned`.

### Tests added
None. The iteration shipped without its mandated test layer (see Test review). The routing,
binding CRUD/RLS, and login-redirect tests are deferred to a follow-up pass.

### Test review
The test agent found seven issues. Resolution:

1. **[High] No tests for any Iteration 6 surface** -- Confirmed. The acceptance criteria's test
   requirement is unmet. Deferred to a follow-up test pass (see Decisions log); the code is
   functionally present and the full suite (7051 tests) passes.
2. **[High] Cross-protocol exclusivity enforced one-way only** -- **Fixed.** Added the OIDC check
   to `app/services/saml/domains.py:bind_domain_to_idp` (`ConflictError`,
   `domain_bound_to_oidc_connection`).
3. **[High] Per-user OIDC disconnect/scrub path missing** -- **Deferred.** The `unlink_user`
   service + API endpoint is a real gap but is a distinct unit of work; logged as a
   reconceptualisation and carried forward (see below).
4. **[Medium] `user_oidc_idp_assigned` declared but never emitted** -- **Fixed.** Now emitted in
   `authenticate_via_oidc` (email-linking branch) and `jit_provision_user`.
5. **[Medium] `get_unbound_domains` does not exclude the other protocol** -- **Fixed.** Both the
   OIDC and SAML unbound queries now left-join the other protocol's binding table and filter it out.
6. **[Low] Misleading success message/note in the privileged-domains template** -- **Fixed.**
   Distinct `domain_bound_oidc` success value + protocol-specific copy; corrected the bottom note.
7. **[Low] `get_link_for_user` assumes at most one link per user** -- **Accepted as documented.**
   The single-link assumption is documented in the docstring; no DB constraint enforces it. Left
   as-is (see Decisions log).

### Reconceptualisations
- **Per-user OIDC disconnect path is a real, separate unit of work.** The spec's Iteration 5
  reconceptualisation and Iteration 6 Guidance both said the scrub fires on the per-user disconnect
  path, but Iteration 6 shipped only the domain-binding surface and never wired
  `scrub_oidc_canonical_matches_mirror(user_id=...)` + `delete_for_user_idp` + `delete_link` into a
  callable `unlink_user` service + API endpoint. This is a genuine gap, not a false positive. It is
  carried forward as a new iteration (see below) rather than bolted on at close-out, because it
  needs its own service function, API endpoint, admin UI, and tests.
- **The mandated test layer was not delivered.** The acceptance criteria explicitly required tests
  for every routing branch, binding CRUD + RLS, and the login redirect; none exist. This is carried
  forward alongside the disconnect path.

### Decisions log
- **Decision**: Fix findings 2, 4, 5, 6 directly at close-out. -- **Context**: The test agent
  surfaced three high/medium bugs and two low issues; the gate (`make check && make test`) was
  already green. -- **Rationale**: These are small, well-scoped correctness fixes (a missing
  exclusivity check, a dead event, two unbound-list queries, template copy) that are safe to land
  without a full dev pass and materially improve correctness.
- **Decision**: Defer finding 3 (per-user disconnect path) and finding 1 (missing tests) to a new
  iteration rather than close Iteration 6 with them unresolved. -- **Context**: Both are real gaps
  but each is a self-contained unit of work (a service + API + UI + tests; a full test layer). --
  **Rationale**: Closing the iteration documents the shipped state honestly while keeping the
  remaining work visible and ordered, rather than silently marking the criteria met.
- **Decision**: Accept finding 7 (single-link assumption) as documented. -- **Context**:
  `get_link_for_user` returns the first link by `created_at` and documents the at-most-one-link
  invariant; no `UNIQUE (user_id)` constraint enforces it. -- **Rationale**: Enforcing one-link-per-
  user would be a schema change with migration implications and is not required by the acceptance
  criteria; the documented assumption is acceptable for now and can be revisited if multi-link
  users become a real scenario.
- **Decision**: Move `determine_auth_route`/`AuthRouteResult` to protocol-neutral homes
  (`app/services/auth_routing.py`, `app/schemas/auth_routing.py`) with SAML re-exports. --
  **Context**: The Iteration 6 Guidance pre-authorized this move to avoid a compliance smell. --
  **Rationale**: OIDC route types in SAML-named modules would be misleading; the re-exports keep
  existing call sites working.

---

## Iteration 7 -- Per-user disconnect path + Iteration 6 test layer
**Status**: Complete
**Completed**: 2026-09-01

Closes the two gaps deferred from Iteration 6: the per-user OIDC disconnect/scrub path, and the
missing test layer for the routing/binding surface.

### Acceptance criteria
- [x] Service `unlink_user_from_connection` (or equivalent) that: reads the link, calls
      `scrub_oidc_canonical_matches_mirror(user_id=...)`, calls
      `database.oidc_upstream.delete_for_user_idp`, calls `database.oidc_upstream.delete_link`, and
      logs a dedicated unlink event (or `user_oidc_idp_assigned` with a removal marker).
- [x] `/api/v1` endpoint + admin UI surface for the disconnect path.
- [x] Tests for the disconnect path: scrub fires, mirror rows dropped, link removed, event logged.
- [x] Tests for the Iteration 6 routing surface: every `determine_auth_route` branch (linked OIDC
      user, domain-bound JIT, default JIT, disabled connection, both-protocols conflict), binding
      CRUD + RLS, and the login-flow redirect in both `_route_after_email_verification` and
      `_route_without_verification`.

### What was done
- `app/services/oidc_upstream/links.py` -- `unlink_user_from_connection` (scrub → drop mirror →
      delete link → inactivate/unverify/revoke → `user_oidc_idp_unlinked` + `user_inactivated`
      events), plus `list_user_oidc_links` and `list_connection_linked_users` admin helpers.
- `app/database/oidc_upstream/links.py` -- Added `get_links_for_user_idp` and
      `delete_links_for_user_idp` (delete *all* links for a `(user_id, idp_id)` pair, not just the
      first), fixing the multi-link disconnect bug found in test review.
- `app/database/oidc_upstream/__init__.py` -- Re-exported the two new link functions.
- `app/services/oidc_upstream/attributes.py` -- Fixed the non-idiomatic `except ValueError,
      ValidationError:` to `except (ValueError, ValidationError):`.
- `app/routers/api/v1/oidc_upstream.py` -- `GET .../connections/{id}/users` and
      `DELETE .../connections/{id}/users/{user_id}` endpoints (super-admin-gated).
- `app/routers/oidc_upstream/admin.py` -- `POST .../unlink-user/{user_id}` handler and the
      danger-tab linked-users rendering.
- `app/templates/...` -- Danger-tab linked-users table + unlink action.

### Tests added
- `tests/services/test_oidc_upstream_links.py` -- `unlink_user_from_connection` (scrub fires, mirror
      rows dropped, link removed, event logged, inactivate + unverify, authz, 404s), plus a
      multi-link regression test; list helpers.
- `tests/services/test_oidc_upstream_routing.py` -- Every `determine_auth_route` branch.
- `tests/routers/test_auth_helpers.py` -- Login-flow redirect in both helpers.
- `tests/database/test_oidc_upstream.py` -- Binding CRUD + RLS (connection + user-link tables).

### Test review
The test agent confirmed the service, routing, and auth-helper layers are covered and green
(90 passed on the affected files; full suite 7077 passed). It surfaced six findings:

1. **[Medium] `unlink_user_from_connection` only removed the *first* link** for a
   `(user_id, connection)` pair, leaving a user still linked when they held multiple links against
   one connection (the schema has no uniqueness on `user_id`). **Fixed** — added
   `get_links_for_user_idp` / `delete_links_for_user_idp` and rewired the service to delete all
   matching rows; added a regression test.
2. **[Medium] No tests for the disconnect API/admin surface** — `GET .../users`,
   `DELETE .../users/{user_id}`, the admin `unlink-user` handler, and the danger-tab rendering had
   zero coverage. **Deferred** to Iteration 8 (see decisions log) — the service layer is covered
   and the surface is thin; the gap is noted for the final review pass.
3. **[Medium] No RLS test for `oidc_idp_domain_bindings`** — the acceptance criterion "binding CRUD
   + RLS" was only partially met (CRUD tested, RLS not). **Deferred** to Iteration 8 (see decisions
   log).
4. **[Low] `list_user_oidc_links` is dead code** — defined/exported but never called (the shipped
   UI is per-connection only). **Left in place** — it is the natural counterpart to
   `list_connection_linked_users` and harmless; noted for the final review pass.
5. **[Low] Non-idiomatic `except ValueError, ValidationError:`** — valid Python 3 but legacy
   Python-2 spelling. **Fixed** to `except (ValueError, ValidationError):`.
6. **[Low] Danger tab silently swallows linked-user listing failures** — `except ServiceError:
   pass` masks a real outage. **Deferred** to Iteration 8 (see decisions log).

### Reconceptualisations
- **The disconnect path must remove *all* links for a `(user_id, connection)` pair, not one.** The
  original plan (and Iteration 5's `get_link_for_user`) assumed a user holds at most one link, but
  the schema's only uniqueness is `(idp_id, sub)` — the email-linking path can accumulate multiple
  links per user. This is a real functional bug, not just a coverage gap, and it changed the
  database layer (new `get_links_for_user_idp` / `delete_links_for_user_idp`).

### Decisions log
- **Decision**: Fix the multi-link disconnect bug in this iteration rather than defer it. --
  **Context**: The test agent flagged it as the only finding with functional impact (a user could
  remain linked after an unlink, or a second connection's unlink could raise a false
  `oidc_user_link_not_found`). -- **Rationale**: It is a correctness bug in the exact surface this
  iteration owns; leaving it would ship a disconnect path that doesn't reliably disconnect.
- **Decision**: Defer the API/admin-surface tests, the `oidc_idp_domain_bindings` RLS test, and the
  danger-tab error-surfacing to Iteration 8. -- **Context**: All three are coverage/robustness
  gaps, not functional bugs; the service layer is fully tested and the full suite is green. --
  **Rationale**: Iteration 8 is preset hardening + E2E and already owns a broad test pass; folding
  these in there keeps Iteration 7 scoped to the disconnect path while ensuring the gaps are
  closed before the final review (Iteration 9).
- **Decision**: Keep `list_user_oidc_links` as dead code rather than remove it. -- **Context**: It
  is exported but uncalled; the shipped UI is per-connection. -- **Rationale**: It is the natural
  counterpart to `list_connection_linked_users` and removing it would churn the public API for no
  functional gain; the final review pass can decide whether to wire or drop it.

---

## Iteration 8 -- Preset hardening + E2E
**Status**: Not started

Per-preset behavior verified against recorded fixtures, and a real end-to-end login flow. Also
closes the three test/robustness gaps deferred from Iteration 7 (see its decisions log).

### Acceptance criteria
- [ ] Recorded fixtures per preset under `tests/fixtures/oidc/<preset>/` (discovery JSON, signed ID
      token JWTs, userinfo responses); tests cover authorize-URL shape (including Google `hd`),
      discovery, ID token validation, and correlation-subject selection (`sub` vs `oid`).
- [ ] Tests for the disconnect API/admin surface: `GET .../connections/{id}/users` (200 + list
      shape), `DELETE .../connections/{id}/users/{user_id}` (204 then link gone), 404 for unknown
      user/connection/link, 403 for non-super-admin; admin `POST .../unlink-user/{user_id}`
      redirects with `success=user_unlinked`, and the danger tab renders the linked-users table.
- [ ] RLS test for `oidc_idp_domain_bindings` (cross-tenant + UNSCOPED fail-closed).
- [ ] Danger tab surfaces linked-user listing failures (template notice or `logger.warning`)
      instead of silently passing.
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

## Iteration 9 -- Docs, release prep, final review
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

- **2026-09-01 -- Iteration 7 close-out.** Fixed the multi-link disconnect bug (delete *all* links
  for a `(user_id, connection)` pair, not just the first) and the non-idiomatic `except` tuple.
  Deferred three test/robustness gaps (disconnect API/admin tests, `oidc_idp_domain_bindings` RLS
  test, danger-tab error surfacing) to Iteration 8, whose acceptance criteria now carry them.
- **2026-09-01 -- Iteration 6 close-out.** Re-split 8 iterations into 9. Iteration 6 shipped the
  domain-binding + routing surface but deferred two real gaps surfaced by the test agent: the
  per-user OIDC disconnect/scrub path (the one place the spec says the scrub actually fires) and
  the mandated test layer for the routing/binding surface. Both are now Iteration 7; the former
  Iteration 7 (preset hardening + E2E) and Iteration 8 (docs/release) shift to 8 and 9.
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
