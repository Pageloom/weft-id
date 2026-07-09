# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Upload-auth temp-file leak (warning-ignored, tracked) |
| Enhancement | 3 | OIDC signing-key rotation surface; OIDC "Deactivated" badge copy; OIDC provider browser e2e (all deferred from OIDC final review) |
| Deps | 1 | pygments (LOW, blocked by upstream) |

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

## [ENHANCEMENT] OIDC signing-key rotation has no operator-facing surface

**Found in:** `app/services/oidc/keys.py` (`rotate_signing_key`, `cleanup_previous_signing_key`)
**Discovered:** 2026-07-06 (OIDC feature final review)
**Category:** API-first / operability
**Decision:** Deferred to the "OIDC Hardening & Certification" backlog item (user call, 2026-07-06).

**Description:** Per-tenant OIDC signing-key rotation is fully implemented at the
service + DB layer (super-admin authorization, overlap grace window, emits
`oidc_signing_key_rotated`) but nothing invokes it — no `/api/v1` endpoint, CLI
command, or background job. Keys still work (lazy provisioning), but an operator
cannot manually rotate a tenant's key or trigger retired-key cleanup. This is an
API-first coverage gap for an implemented capability.

**Suggested fix:** Expose rotation (and `cleanup_previous_signing_key`) via a
super-admin `/api/v1` endpoint and/or a `python -m app.cli` command, and wire a
background sweep for expired retired keys. Bundle with the OIDC Hardening item.

---

## [ENHANCEMENT] OAuth2 App status badge reads "Inactive" for a deactivated app

**Found in:** `app/templates/integrations_app_detail.html` (and the apps list view)
**Discovered:** 2026-07-06 (OIDC feature final review, tech-writer)
**Category:** Copy consistency
**Decision:** Deferred to a separate cross-cutting copy pass (user call, 2026-07-06).

**Description:** A deactivated App shows a status badge labelled "Inactive" while
every action verb around it says "Deactivate/Reactivate". Per the project's
"deactivated" terminology preference, the badge for a deactivated app should read
"Deactivated"; "inactive" should be reserved for the idle condition. Pre-existing
and shared across the apps list + detail views (not introduced by the OIDC
feature), so a correct fix touches shared client-status copy in both places.

---

## [ENHANCEMENT] No browser-level e2e for the OIDC provider flow

**Found in:** `tests/e2e/` (coverage gap)
**Discovered:** 2026-07-06 (OIDC feature final review, test)
**Category:** Test coverage
**Decision:** Deferred (user call, 2026-07-06). The full flow is covered at the
TestClient integration level; this is defense-in-depth.

**Description:** The e2e suite has no Playwright test driving a real browser
through `/oauth2/authorize` (session-cookie boundary) → token exchange →
`/userinfo` (bearer boundary) for an `oidc_enabled` client. Worth a single
happy-path e2e if the OIDC surface grows. Note: refresh tokens intentionally do
NOT re-evaluate group access (standard OAuth2 semantics, documented in
`app/services/oidc/access.py`) — that is by design, not a gap.

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
