# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 2 | File Structure (pre-existing); composite created_by FKs break user delete |
| Low | 8 | Upload-auth temp-file leak (warning-ignored, tracked); expired OAuth2 tokens never swept; back-channel claim tests race the dev worker; RFC 7592 update can undo admin decisions; outbound fetch negative cache; pre-sid sessions not revocable; OIDC test gaps; OIDC glossary/screenshots |

Note: the HIGH CSRF-never-enforced finding (middleware ordering, discovered 2026-09-14 on
the oidc-conformance branch) was resolved on 2026-09-14; see ISSUES_ARCHIVE.md.

**Last code review:** 2026-09-06 (nav-restructure branch vs main, `/code-review`; 5 findings logged, all resolved 2026-09-06 -- see ISSUES_ARCHIVE.md)

Note: the `[DEPS] pygments` entry was resolved in 1.11.0 (2026-07-12) — pymdown-extensions
11.0.1 unblocked the 2.20.0 bump and the pin is gone; see ISSUES_ARCHIVE.md.

Note: the three OIDC security findings from the 2026-07-09 scan (bearer-validation
Argon2 DoS, OIDC access-revocation lag, authorize flow skipping is_active) were
resolved on the oidc-provider branch (2026-07-12, migration 0056); see
ISSUES_ARCHIVE.md.

Note: the three OIDC final-review enhancements (signing-key rotation surface,
"Deactivated" badge copy, OIDC provider browser e2e) and the HIGH
silently-broken-UNSCOPED-worker-sweeps bug were resolved on the oidc-provider
branch (2026-07-09); see ISSUES_ARCHIVE.md.

Note: the six inbound-SCIM final-review items (cross-IdP rebind audit event, actor
consistency, private-helper import boundary, `list_active_tokens` dead code, canonical-email
validation, Pydantic `max_length`) plus the project-wide proxy-headers / forwarded-host trust
boundary were resolved on the inbound-scim branch (2026-05-29); see ISSUES_ARCHIVE.md.

**Last security scan:** 2026-07-09 (full sweep of the oidc-provider branch vs main, all OWASP categories: OIDC signing keys/JWKS/discovery, ID-token issuance, userinfo, client access control, migrations 0051-0055, templates, worker sweeps. Overall well-defended: parameterized SQL, strict RLS + hardened SECURITY DEFINER accessors, encrypted key material, PKCE/one-time codes intact, CSRF on all new forms, bounded inputs with matching DB CHECKs, regression hunt against ISSUES_ARCHIVE patterns clean. Found 2 MEDIUM + 1 LOW, all resolved 2026-07-12; see ISSUES_ARCHIVE.md)
**Previous security scan:** 2026-06-21 (targeted 60-day sweep of forward-auth proxy, inbound/outbound SCIM, WebAuthn, and user-attributes→SAML flow; forward-auth, inbound SCIM, and WebAuthn verified well-defended; the 1 HIGH SSRF + 2 MEDIUM attribute-provenance + Low DiD bundle it found have since been resolved, see ISSUES_ARCHIVE.md)
**Last compliance scan:** 2026-06-21 (automated checker clean, 0 violations across 1612 files; targeted 60-day manual sweep of SCIM, WebAuthn, attributes/auth-policy/settings, forward-auth proxy, and migrations 0031-0048; the 6 warning-level judgment findings have since been resolved, see ISSUES_ARCHIVE.md)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-06-20 (cryptography 48.0.0→48.0.1, python-multipart 0.0.29→0.0.31, pip 26.1.1→26.1.2, msgpack 1.1.2→1.2.1, starlette 1.0.1→1.3.1 bumped, clearing all 6 HIGH/MED CVEs; full suite green; the pygments `<2.20` pin has since been dropped in 1.11.0, see ISSUES_ARCHIVE.md)
**Code scanning (CodeQL):** re-enabled 2026-07-12 after being disabled 2026-03-24 (four months unscanned, covering the OIDC provider and forward-auth releases). Default setup, weekly, languages python/javascript-typescript/actions. The 2026-07-12 audit of the historical backlog found ~200 alerts, all verified false positives except one real info leak in passkey registration (fixed, released in 1.11.0) and a workflow `GITHUB_TOKEN` over-grant (fixed). The 39 open `py/url-redirection` alerts were resolved on 2026-08-18 by the `safe_redirect` helper (PR #146) — the alert class collapsed at the source, with no dismissals and the rule still in the suite; see ISSUES_ARCHIVE.md.
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-09-06 (nav-restructure branch: app copy sweep across the 64 changed templates plus a docs spot-check. 7 stale docs breadcrumbs/labels fixed directly in `docs/`; 4 new issues found (duplicate Security/Branding tab rows, headings still using pre-restructure section names, Add User vs New Group verb split, Requests badge accessibility), all resolved 2026-09-06, see ISSUES_ARCHIVE.md)
**Previous copy review:** 2026-04-24 (terminology sweep: "two-step verification" → "sign-in strength" / "sign-in methods" where passkeys make "two-step" inaccurate)

---

## [REFACTOR] File Structure: groups/idp.py split candidate at 710 lines

**Found in:** `app/services/groups/idp.py`
**Impact:** Medium
**Category:** File Structure
**Description:** This file handles two distinct concerns: group creation/discovery (create_idp_base_group, get_or_create_idp_group, _ensure_umbrella_relationship, invalidate_idp_groups) and membership management (sync_user_idp_groups, ensure_user_in_base_group, remove_user_from_base_group, move_users_between_idps). At 710 lines with 15 public functions, it's at the limit of maintainability.
**Why It Matters:** The two concerns are intertwined but distinct. Splitting improves traversability and makes each module's purpose clear.
**Deferred reason:** The test suite patches `services.groups.idp.database` as a single mock to intercept calls across both lifecycle and membership functions. Splitting the module would require patching two submodules' `database` references in ~40 test locations, doubling mock boilerplate. The file should be split after refactoring tests to use proper fixtures.
**Suggested Refactoring:** Split into two modules within the existing groups package:
- `idp_lifecycle.py` (~350 lines): group lifecycle and discovery
- `idp_membership.py` (~350 lines): sync, base group membership, cross-IdP moves
**Files Affected:** `app/services/groups/idp.py`, `app/services/groups/__init__.py`, tests

---

## [BUG] Upload routes leak the parsed file when super-admin check rejects

**Discovered:** 2026-06-20 (surfaced by enabling `filterwarnings = ["error"]`)
**Severity:** Low (no production impact; currently warning-ignored + tracked)
**Source:** pytest `PytestUnraisableExceptionWarning` (`SpooledTemporaryFile.__del__`)

On routes that take an `UploadFile` under a router-level `require_super_admin`
dependency, FastAPI parses (buffers) the multipart body before the dependency
runs. When the dependency rejects, the file param is never bound, so its
`SpooledTemporaryFile` is never closed and is reclaimed only at GC, where
`__del__` raises an unraisable exception. In tests this attaches
non-deterministically to whatever test is running and fails the suite under
error-mode warnings.

**Impact:** None in production (small in-memory temp file, GC-time noise). The
only observable effect is the test warning.

**Current handling:** A narrowly-scoped `filterwarnings` ignore in
`pyproject.toml` (matched to the `SpooledTemporaryFile` message only) keeps the
suite warning-clean. This is a deliberate, documented exception to the
warnings-are-errors policy.

**Real fix (deferred):** Restructure super-admin-guarded upload routes so the
body is not buffered before the access check (e.g. in-handler auth for upload
routes, or a mechanism that closes form files on dependency rejection). The
obvious fix (parse the form after the auth check via `async with request.form()`)
collides with the CSRF middleware, which already owns multipart body parsing, so
this needs a coordinated change. When fixed, remove the `filterwarnings` ignore.

**Files Affected:** `app/routers/saml_idp/admin.py` (and the other 5 `UploadFile`
routes share the latent pattern), `app/middleware/csrf.py`, `pyproject.toml`

---

---

## [BUG] Composite `created_by` foreign keys null `tenant_id` on user delete

**Discovered:** 2026-09-27 (oidc-conformance Iteration 8a, while testing cascades)
**Severity:** Medium (deleting a user who created one of these rows fails)
**Found in:** ten foreign keys of the form
`FOREIGN KEY (created_by, tenant_id) REFERENCES users(id, tenant_id) ON DELETE SET NULL`

Without a column list, `ON DELETE SET NULL` nulls **both** referencing columns,
including the row's `tenant_id` (NOT NULL). Deleting the referenced user then
fails with a not-null violation instead of clearing `created_by`. Observed on
`oidc_idp_connections` (deleting the connection's creator); the same shape is
on `tenant_privileged_domains`, `tenant_security_settings` (`updated_by`),
`saml_identity_providers`, `saml_idp_domain_bindings`, `saml_sp_certificates`,
`oauth2_clients`, `service_providers`, `domain_group_links`, and
`oidc_idp_domain_bindings`. Not verified whether the user-delete service
blocks the case first (e.g. by refusing to delete admins).

**Suggested fix:** Postgres 15+ supports `ON DELETE SET NULL (created_by)`.
Re-create each constraint with the column list (add the new one `NOT VALID`,
validate, drop the old one). Where `created_by` is itself NOT NULL
(`oidc_idp_connections`), decide between making it nullable and blocking the
delete with a clear error.
**Files Affected:** a new migration; possibly `app/services/users/crud.py`

---

## [BUG] Expired OAuth2 access and refresh tokens are never deleted

**Discovered:** 2026-09-26 (oidc-conformance Iteration 4)
**Severity:** Low (storage growth only; expired rows are never accepted)
**Found in:** `app/database/oauth2/tokens.py` (`cleanup_expired_tokens`)

`cleanup_expired_tokens` exists but nothing calls it, so every access token
(1 h) and refresh token (30 d) row stays in `oauth2_tokens` forever. Validation
filters on `expires_at > now()`, so nothing expired is ever honoured; the cost is
unbounded table and index growth. Authorization codes had the same gap; since
Iteration 4 keeps redeemed codes (marked `consumed_at`) for reuse detection,
`create_authorization_code` now sweeps the tenant's expired codes inline.

**Suggested fix:** A periodic worker sweep. `oauth2_tokens` has the strict
(non-NULLIF) RLS policy, so a cross-tenant sweep needs a SECURITY DEFINER
function (see THOUGHT_ERRORS "Cross-Tenant Queries"), or an inline per-tenant
sweep on the token-issuance path like the one codes use.
**Files Affected:** `app/database/oauth2/tokens.py`, a new job in `app/jobs/`

---

## [SECURITY] RFC 7592 client update can undo admin decisions; registration token never rotates

**Discovered:** 2026-10-02 (oidc-conformance final review, security L2)
**Severity:** Low
**Found in:** `app/services/oauth2_registration.py` (`update_client_configuration`),
`app/database/oauth2/registration.py` (`replace_registered_client`)

After an admin narrows a dynamically registered client (group access, device grant off,
redirect URIs trimmed), the holder of its registration access token can PUT the metadata
back: re-add the device grant, add redirect URIs, change name and logo. The
`oauth2_client_registration_updated` event logs only name, redirect URIs and subject type.
The token never expires and an admin cannot reset it short of deleting the client.

**Fix direction:** treat admin-set flags (device grant, PAR) as a ceiling a PUT cannot
raise; log every changed field; rotate the registration access token on each update
(RFC 7592 allows returning a new one) and give admins a reset; consider flagging the client
for re-review when its redirect URIs change.

---

## [SECURITY] Hardening: outbound fetch failures are not cached, no per-client in-flight cap

**Discovered:** 2026-10-02 (oidc-conformance final review, security M3 remainder)
**Severity:** Low
**Found in:** `app/services/oauth2_request_objects.py` (`_fetch`),
`app/services/oauth2_client_auth.py` (`_fetch_jwks`), `app/services/oidc/subject.py`

The slow-drip half of M3 is fixed (`build_safe_client(total_timeout=)` bounds every fetch
to 10s overall). Left open: a client whose `request_uri` or `jwks_uri` is slow or failing is
fetched again on every authorize/token request (no negative cache), and nothing limits
concurrent fetches per client, so a registered client can still keep a handful of threads
busy for up to 10s each.

**Fix direction:** cache a failed fetch for ~30s per (tenant, client, URI); allow one
in-flight fetch per client (others fail fast or wait on it).

---

## [SECURITY] Sessions from before `sid` existed cannot be revoked server-side

**Discovered:** 2026-10-02 (oidc-conformance final review, security hardening note)
**Severity:** Low (same as `main`)
**Found in:** `app/routers/auth/logout.py` (`terminate_session`), `utils.session.ensure_session_id`

A session cookie minted before the `sid` work has no session id until something calls
`ensure_session_id` (issuing an OIDC code does). Signing out of such a session clears the
cookie but records no revocation, so a copied cookie stays valid until it expires.

**Fix direction:** mint a `sid` on the first authenticated request that lacks one (in the
auth dependency), so every live session becomes revocable.

---

## [TEST] OIDC branch coverage gaps left after the final review

**Discovered:** 2026-10-02 (oidc-conformance final review, test reviewer)
**Severity:** Low

- Integrations role gate: no test that a `user` posting to the new App routes
  (authentication, subject, consent revoke) or the b2b routes in
  `app/routers/integrations.py` is redirected to `/dashboard` with the service never called.
  Services enforce admin and are tested; this is defense in depth only.
- `app/services/oauth2_client_auth.py`: no test for a `private_key_jwt` client whose keys
  fail to load first and load after the refetch (branch 282->290).
- `app/services/oauth2_registration.py`: no test asserts `get_registration_settings` and
  `list_initial_access_tokens` call `track_activity`.
- E2E: device verification (`/device` anonymous, login, stashed code, approve), remembered
  consent across two sign-ins, the form_post auto-submit under CSP, and upstream back-channel
  logout ending a live browser session are covered only by the conformance suite and unit
  tests, not by `make e2e`.

---

## [DOCS] Glossary entries and screenshots for the OIDC hardening features

**Discovered:** 2026-10-02 (oidc-conformance final review, tech-writer)
**Severity:** Low

- `docs/glossary.md` has no entries for: pairwise subject identifier / sector identifier,
  pushed authorization request (PAR), request object, back-channel / front-channel logout and
  logout token, device authorization grant, initial access token, token introspection /
  revocation, private key JWT. Short entries linking to the integration pages.
- Screenshots would help: consent screen with "Already allowed", the device code entry and
  confirm pages, the Client Registration page, the app detail "Subject Identifiers" and
  "Back-Channel Logout Deliveries" sections, the "Sign in again?" confirmation.
- Release step (not a defect): `docs/conformance/oidc.md` labels the last run "1.12.0
  (`446d4263`)" because that is the version in `pyproject.toml`. Regenerate it with
  `make oidc-conformance-report ARGS="--write-docs"` after the version bump, per
  `docs/VERSIONING.md`, or teach the report to label untagged builds.

---

## [TEST] Back-channel delivery claim tests race the running dev worker

**Discovered:** 2026-10-01 (oidc-conformance Iteration 11b, `make quality-all`)
**Severity:** Low (flaky test, no production impact)
**Found in:** `tests/database/test_oauth2_backchannel.py` (`test_claim_respects_limit`, and in
principle every test that queues a delivery and then calls `claim_due_deliveries`)

Unit tests run against the dev database (`appdb`, see `tests/conftest.py`). The dev worker
container runs `deliver_oidc_backchannel_logouts` every few seconds, and
`list_tenants_with_due_backchannel_logouts()` returns every tenant with a due delivery, test
tenants included. When the worker leases a row between the test queueing it and the test's own
claim, the test sees fewer rows (`assert 1 == 2`). Seen once in a full parallel run; passes in
isolation (3/3).

**Suggested fix:** Isolate tests from the worker rather than patch the test. Options: run unit
tests against a separate database (`appdb_test`) the worker never connects to; or stop the
worker for the test run (`make test` could `docker compose stop worker` and restart it after).
A test-only filter in the SQL function is not acceptable (production code must not know about
test tenants). Check other worker-swept tables (session sweeps, token cleanup) for the same race
once the isolation exists.

**Files Affected:** `tests/conftest.py`, `Makefile` (or the dev compose), possibly
`tests/database/test_oauth2_backchannel.py`
