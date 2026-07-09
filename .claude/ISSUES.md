# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Silently-broken UNSCOPED worker sweeps (strict RLS returns 0 rows) |
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Upload-auth temp-file leak (warning-ignored, tracked) |
| Deps | 1 | pygments (LOW, blocked by upstream) |

Note: the three OIDC final-review enhancements (signing-key rotation surface,
"Deactivated" badge copy, OIDC provider browser e2e) were resolved on the
oidc-provider branch (2026-07-09); see ISSUES_ARCHIVE.md.

Note: the six inbound-SCIM final-review items (cross-IdP rebind audit event, actor
consistency, private-helper import boundary, `list_active_tokens` dead code, canonical-email
validation, Pydantic `max_length`) plus the project-wide proxy-headers / forwarded-host trust
boundary were resolved on the inbound-scim branch (2026-05-29); see ISSUES_ARCHIVE.md.

**Last security scan:** 2026-06-21 (targeted 60-day sweep of forward-auth proxy, inbound/outbound SCIM, WebAuthn, and user-attributes→SAML flow; forward-auth, inbound SCIM, and WebAuthn verified well-defended; 1 HIGH SSRF + 2 MEDIUM attribute-provenance + Low DiD bundle logged below)
**Last compliance scan:** 2026-06-21 (automated checker clean, 0 violations across 1612 files; targeted 60-day manual sweep of SCIM, WebAuthn, attributes/auth-policy/settings, forward-auth proxy, and migrations 0031-0048; 6 warning-level judgment findings logged below, no blockers)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-06-20 (cryptography 48.0.0→48.0.1, python-multipart 0.0.29→0.0.31, pip 26.1.1→26.1.2, msgpack 1.1.2→1.2.1, starlette 1.0.1→1.3.1 bumped, clearing all 6 HIGH/MED CVEs; full suite green; pygments still pinned `<2.20`, see [DEPS] entry below)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-24 (terminology sweep: "two-step verification" → "sign-in strength" / "sign-in methods" where passkeys make "two-step" inaccurate)

---

## [BUG] Four periodic worker sweeps are silent no-ops: UNSCOPED queries against strict-RLS tables see zero rows

**Discovered:** 2026-07-09 (while building the OIDC signing-key cleanup sweep)
**Severity:** High (certificate auto-rotation, certificate cleanup, SAML metadata refresh, and idle-user auto-inactivation have never run in any `appuser` deployment)
**Verified:** empirically on the dev DB — as `appuser` with no `app.tenant_id` set, `sp_signing_certificates` / `saml_idp_sp_certificates` / `saml_identity_providers` / `tenant_security_settings` all return 0 rows while ground truth (as `postgres`) shows 5 certs, 3 IdPs, 143 SPs.

The `UNSCOPED` sentinel only skips `SET LOCAL app.tenant_id`; it does not bypass
RLS. Tables with the strict tenant-isolation policy
(`tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`) fail
**closed** when the setting is unset, so any UNSCOPED select from the worker
(which connects as `appuser`, `NOBYPASSRLS` — both dev and `deploy/docker-compose.yml`)
returns nothing. Only tables with the permissive-when-unscoped CASE policy
(`event_logs`, `export_files`, `forward_auth_nonces`, `scim_push_queue`,
`scim_sync_log`, `scim_inbound_tokens`, `sp_scim_credentials`, `protected_domains`)
or no RLS (`tenants`, `bg_tasks`, `saml_debug_entries`) are legitimately
readable UNSCOPED.

**Broken call sites (each makes its worker job a silent no-op):**

1. `database/sp_signing_certificates.py` `get_certificates_needing_rotation_or_cleanup()` → `jobs/rotate_certificates.py` never auto-rotates or cleans up SP signing certificates
2. `database/saml/idp_sp_certificates.py` `get_idp_sp_certificates_needing_rotation_or_cleanup()` → same job, per-IdP SP certificates
3. `database/saml/providers.py` `get_idps_with_metadata_url()` → `jobs/refresh_saml_metadata.py` never refreshes any IdP metadata
4. `database/security.py` `get_all_tenants_with_inactivity_threshold()` → `jobs/inactivate_idle_users.py` never inactivates idle users

The jobs log "No X need rotation/cleanup" daily, which masks the failure. Unit
tests mock these DB functions, and the database integration tests never covered
them, so nothing caught it.

**Sanctioned fix pattern (established by migration 0040):** route each
cross-tenant sweep through a `SECURITY DEFINER` function owned by `appowner`
(table owners are exempt from RLS), pinned `search_path`, exposing only the
columns the sweep needs, `GRANT EXECUTE ... TO appuser`. Migration 0040 did
exactly this for the SCIM sync-log cleanup after reverting the too-wide policy
from 0037. Migration 0054 (OIDC signing-key cleanup) follows the same pattern.
Fix is one migration adding four functions plus updating the four database
functions to select from them, plus database-layer integration tests that
exercise the real (non-mocked) query path as `appuser`.

**Also fix while there:** the "Cross-Tenant Queries: Use UNSCOPED" entry in
`.claude/THOUGHT_ERRORS.md` claims UNSCOPED "gives the query cross-tenant
visibility" — true only for permissive-policy tables; it should point to the
SECURITY DEFINER pattern for strict tables.

**Files Affected:** `db-init/migrations/` (new), `app/database/sp_signing_certificates.py`,
`app/database/saml/idp_sp_certificates.py`, `app/database/saml/providers.py`,
`app/database/security.py`, `.claude/THOUGHT_ERRORS.md`, `tests/database/`

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

## [DEPS] pygments 2.19.2 — CVE-2026-4539 (LOW, blocked by upstream)

**Discovered:** 2026-05-12, re-confirmed 2026-05-15
**Severity:** Low
**Source:** `python dev/deps_check.py`

**CVE-2026-4539** (GHSA-5239-wwwm-4pmq): ReDoS in `AdlLexer`
(`pygments/lexers/archetype.py`).

**Exploitability in this project: NONE.** Pygments is only used to
syntax-highlight code blocks in the docs site (built at image time, not
user-facing input). No Adl/archetype files are rendered.

**Remediation: BLOCKED.** Pinned `<2.20` in `pyproject.toml` because
`pymdownx.superfences` (via `zensical`) crashes on pygments 2.20.0
(`filename=None` regression). Wait for an upstream `pymdownx.superfences`
fix or swap to the new API before bumping.

Does not block `make check` (deps_check only fails on critical/high).

**Files Affected:** `pyproject.toml`, `poetry.lock`

---
