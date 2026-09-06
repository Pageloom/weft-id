# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low/Medium | 1 | `form-input-length` checker misses `= Form("")` syntax, 33 unbounded params (pre-existing) |
| Low | 1 | Upload-auth temp-file leak (warning-ignored, tracked) |

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
**Last copy review:** 2026-09-06 (nav-restructure branch: app copy sweep across the 64 changed templates plus a docs spot-check. 7 stale docs breadcrumbs/labels fixed directly in `docs/`; 4 new issues logged below — duplicate Security/Branding tab rows, headings still using pre-restructure section names, Add User vs New Group verb split, Requests badge accessibility)
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

## [COMPLIANCE] `form-input-length` checker misses `= Form("")` default-value syntax

**Discovered:** 2026-09-06 (nav-restructure branch, Step 8 compliance and security reviews, found
independently by both)
**Severity:** Low/Medium
**Source:** Manual review during the nav-restructure feature's final Step 8 pass. Pre-existing
on `main` (confirmed byte-identical for the affected lines) -- the nav restructure touched some
of the affected files (moving routes) but did not introduce the unbounded parameters.

`dev/compliance_check.py`'s `form-input-length` rule (`_extract_form_call_from_annotation`) only
inspects the `Annotated[str, Form(...)]` subscript form. It does not see the equivalent
`name: str = Form("")` default-value form, so parameters written that way are invisible to
`make check` even though CLAUDE.md's rule ("every `Form()` parameter in route handlers must
specify `max_length`") covers them. 33 such parameters currently exist with no `max_length`: 12 in
`app/routers/integrations.py`, 20 in `app/routers/saml_idp/admin.py`, 1 in
`app/routers/saml_idp/sso.py`. The most notable is `metadata_xml: str = Form("")` on the SAML SP
metadata-import routes -- an unbounded body reaching an XML parser. All 33 are behind
admin/super_admin auth, limiting real-world impact.

**Suggested fix:** Two-part -- (1) extend `dev/compliance_check.py`'s form-input-length check to
also recognize the `= Form(...)` default-value syntax, so this class of gap can't recur silently;
(2) add `max_length` to the 33 existing parameters, using this project's standard limits (see
CLAUDE.md's rule 10).

**Files Affected:** `dev/compliance_check.py` (checker), `app/routers/integrations.py`,
`app/routers/saml_idp/admin.py`, `app/routers/saml_idp/sso.py`

---
