# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low/Medium | 3 | `form-input-length` checker misses `= Form("")` syntax, 33 unbounded params (pre-existing); legacy 301s drop query strings; per-instance legacy URLs 404 instead of 301 |
| Low | 9 | Upload-auth temp-file leak (warning-ignored, tracked); stale "Integrations" template copy; page headings out of step with new nav; Add User vs New Group verb split; Requests badge accessibility/reach; section index routes lack bare-path form; degenerate single-tab third-level nav; hardcoded role tuple in `users_list.html`; nav-restructure backlog item not archived |

**Last code review:** 2026-09-06 (nav-restructure branch vs main, `/code-review`; 5 findings logged below under `[REVIEW]`)

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

## [COPY] Stale "Integrations" page titles after the nav restructure

**Found in:** `app/templates/integrations_apps.html:3`, `app/templates/integrations_app_detail.html:3`,
`app/templates/integrations_b2b.html:3` and `:12`, `app/templates/integrations_b2b_detail.html:3`
**Severity:** Low
**Description:** The nav-restructure feature (`nav-restructure` branch, Iterations 1-4) removed
the `Integrations` top-level container entirely -- these pages now live at
`Applications > OAuth2 / OIDC` and `Applications > Service Accounts`. The `<title>` blocks on all
four templates still read `"... - Integrations - {{ site_title }}"` (browser tab title), and the
B2B templates' on-page `<h1>` and "Back to B2B" link still say bare `B2B` rather than `Service
Accounts`. This was caught during Iteration 5's docs pass (docs-only scope; the docs describing
these pages have been updated in `docs/admin-guide/integrations/apps.md` and `b2b.md`), but the
app template copy itself was out of scope for that pass.
**Current:** `{% block title %}B2B - Integrations - {{ site_title }}{% endblock %}` (and similarly
for the other three files); `<h1>B2B</h1>`.
**Suggested:** Drop "Integrations" from all four `<title>` blocks (e.g. `Apps - {{ site_title }}`,
`B2B - {{ site_title }}`, or rename to match the new nav labels `OAuth2 / OIDC` / `Service
Accounts`). Decide whether the on-page "B2B" copy should also become "Service Accounts" to match
the new nav label, or stay as the underlying technical term (same question already decided for
"Privileged Domains" and "Protected Domains", which kept their on-page copy -- see
`.claude/ITERATION_nav_restructure.md` Iteration 2/3 decision logs).
**Scope:** 4 template files, `<title>` blocks plus B2B's `<h1>` and back-link.

---

## [COPY] Page headings and buttons still use pre-restructure section names

**Found in:** `app/templates/settings_security_base.html:3,10`,
`app/templates/settings_privileged_domains.html:3,8,50,198`,
`app/templates/saml_idp_sp_list.html:12`, `app/templates/saml_idp_list.html:22,81`,
`app/templates/saml_idp_form.html:3,15`, `app/templates/saml_idp_base.html:3`,
`app/pages.py:260,301,308`
**Severity:** Low
**Description:** Iterations 2 and 3 deliberately deferred on-page copy to the docs pass, and the
docs pass deferred app templates back to a copy review. These are the leftovers (the four
`integrations_*.html` files are tracked in the separate entry above, not repeated here).

| Where | Current | Problem | Suggested |
|-------|---------|---------|-----------|
| `settings_security_base.html:3` | `Security Settings - {{ site_title }}` | Security is no longer under Settings | `Security - {{ site_title }}` |
| `settings_security_base.html:10` | "Security settings updated." | same | "Security settings updated." is fine as prose; optional |
| `settings_privileged_domains.html:3,8` | title/`<h1>` "Privileged Domains" | nav label is now "Domain Routing" | decide: rename to "Domain Routing", or keep and accept the split |
| `saml_idp_sp_list.html:12` | `<h1>` "Service Providers (apps)" | the section is now literally **Applications**, and **Forward Auth > Apps** is a sibling tab, so "(apps)" reads as a cross-reference to the wrong page | "Service Providers" (drop the parenthetical) |
| `saml_idp_list.html:22` | button "Add Identity Provider" | ambiguous next to the OIDC sibling tab, whose button says "Add OIDC Provider" | "Add SAML Provider" |
| `saml_idp_list.html:81` | empty state "No identity providers configured" | same; OIDC's says "No OIDC providers configured" | "No SAML providers configured" |
| `saml_idp_form.html:3,15` | "Add Identity Provider" | same | "Add SAML Provider" |
| `saml_idp_base.html:3` | `{{ idp.name }} - Identity Provider` | OIDC's says `- OIDC Provider` | `{{ idp.name }} - SAML Provider` |
| `app/pages.py:301,308` | "Add Identity Provider" / "Identity Provider Details" | same, and these feed breadcrumbs | "Add SAML Provider" / "SAML Provider Details" |
| `app/pages.py:260` | Requests child labelled "User Attributes" | sits two rows from **Directory > Attributes** (the catalog page, `<h1>` "User attributes"); the queue page's own `<h1>` is "Incomplete user profiles" | "Profile Completion", matching the page's own heading and disambiguating from the catalog |

Iteration 2's acceptance criteria called for "symmetric naming" between the SAML and OIDC tabs.
The list `<h1>`s were made symmetric; the buttons, empty states, form headings, detail titles, and
`pages.py` titles were not.
**Scope:** 6 templates plus 3 `title=` strings in `app/pages.py`. The `pages.py` changes need
matching updates in `tests/test_pages.py` if any assert on those titles. Renaming the Requests
child label does not change its path, so no redirect work.

---

## [COPY] "Add User" and "+ New Group" use different verbs for the same action

**Found in:** `app/templates/users_list.html:99`, `app/templates/groups_list.html:13`
**Severity:** Low
**Description:** Iteration 1 removed "Add User" and "Add Group" from the nav and put buttons on
the list pages instead. The new Users button says **Add User**; the pre-existing Groups button
says **+ New Group**. They are now adjacent tabs in the same Directory section, so the split is
visible. Groups is internally inconsistent on its own: `app/pages.py:174` calls the page "Add
Group", `groups_new.html:3` titles it "New Group", its `<h1>` is "Create New Group", and its
submit button is "Create Group" — four labels for one action.
**Current:** "Add User" / "+ New Group" / "Add Group" / "New Group" / "Create New Group" /
"Create Group".
**Suggested:** Standardise on "Add X" throughout, matching the rest of the app ("Add Service
Provider", "Add OIDC Provider", "Add Members"): button "Add Group", page title "Add Group",
`<h1>` "Add Group", submit "Add Group". Drop the leading "+" so the two list pages match.
**Scope:** `groups_list.html`, `groups_new.html`, and optionally the "New Group" modal heading in
`groups_list.html:165`.

---

## [COPY] Requests badge has no text alternative and is invisible outside Directory

**Found in:** `app/templates/base.html:147-149`, `app/utils/template_context.py:19-35`
**Severity:** Low
**Description:** The new pending-count badge renders only inside the level-2 sub-nav strip, which
only appears once the admin is already somewhere under **Directory**. An admin sitting on the
Dashboard, in Audit, or in Applications never sees that anything is pending, which is most of the
value a badge is supposed to provide. The badge is also a bare number with no accessible name: a
screen reader announces "Requests 3" with no indication of what the 3 counts.
**Current:** `<span ...>{{ nav.requests_badge_count }}</span>` inside the Requests sub-nav link.
**Suggested:** Add `title="{{ nav.requests_badge_count }} pending request(s)"` (or a visually
hidden span) so the number has a label. Separately, decide whether the count should also surface
on the top-level **Directory** nav item so it is visible from anywhere.
**Scope:** `app/templates/base.html`; a Directory-level badge would also touch
`app/utils/template_context.py`.

Note: the previously-noted side observation (two uncached service calls on every admin page
render, even where the badge cannot render) was fixed 2026-09-06 -- `get_template_context()` now
gates `_get_requests_badge_count()` on the active top-level section being Directory. This entry's
remaining scope is copy/accessibility only (no text alternative, invisible outside Directory).

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

## [REVIEW] Legacy 301 handlers drop query strings

**Discovered:** 2026-09-06 (nav-restructure branch, `/code-review`)
**Severity:** Low/Medium
**Found in:** `app/routers/legacy_redirects.py:30` (all 45 handlers)

Every handler takes no `Request` and redirects to a fixed literal, so parameters the old routes
honored are silently dropped. `GET /admin/audit/events?tiers=security&page=3&size=100` lands on
`/audit/events` with default filters. `/admin/groups/list?view=graph&search=Eng` lands on the plain
list. `/admin/todo/user-attributes?filter_key=phone` loses its filter.
`/admin/audit/user-export?success=export_started` loses its flash.

The module docstring claims the compliance check forces literal `RedirectResponse` targets. That is
a misreading: `check_redirect_validation_violations` only inspects `RedirectResponse` calls, so
`safe_redirect(location, status_code=301)` is permitted, and `routers/groups/members.py:94-98`
already uses exactly that pattern with `request.url.query` appended.

**Suggested fix:** Replace the 45 handlers with a single table-driven handler that appends
`request.url.query` and returns `safe_redirect(new_path, status_code=301)`. See the next entry for
folding per-instance URLs into the same handler.

**Files Affected:** `app/routers/legacy_redirects.py`, `tests/routers/test_legacy_redirects.py`

---

## [REVIEW] Per-instance legacy URLs 404 instead of 301

**Discovered:** 2026-09-06 (nav-restructure branch, `/code-review`)
**Severity:** Low/Medium
**Found in:** `app/routers/legacy_redirects.py:92`, `.claude/BACKLOG.md:1117`

`legacy_redirects.py` contains no `{` path parameter anywhere, so every old per-instance URL that
rendered on `main` now 404s: `/admin/audit/events/<uuid>`, `/admin/groups/<gid>/membership`,
`/admin/settings/identity-providers/<idp>/certificates`,
`/admin/settings/service-providers/<sp>/groups`, `/admin/integrations/apps/<client_id>`, and the
OIDC, proxy-app, and SAML-debug detail pages. Comments and CHANGELOG describe the omission as
deliberate, but the backlog acceptance criterion reads "Every old URL under `/admin/settings/*`,
`/admin/integrations/*`, `/admin/todo/*` ... returns a 301".

**Suggested fix:** A catch-all `@router.get('/admin/{rest:path}')` that rewrites against a
~15-entry longest-prefix-first table, re-appends `request.url.query`, and returns
`safe_redirect(new_path, default='/dashboard', status_code=301)` covers static, dynamic, and
query-string cases in roughly 40 lines and replaces the 45 stubs. If the 404 behaviour is kept
instead, amend the acceptance criterion when archiving the backlog item.

**Files Affected:** `app/routers/legacy_redirects.py`, `tests/routers/test_legacy_redirects.py`,
`.claude/BACKLOG.md` (or its archive entry)

---

## [REVIEW] Section index routes register only the trailing-slash form

**Discovered:** 2026-09-06 (nav-restructure branch, `/code-review`)
**Severity:** Low
**Found in:** `app/routers/audit.py:42` and the sibling index routes for `/security`,
`/identity-providers`, `/settings`, `/applications`; `app/templates/base.html:95,144`

Enumerating app routes yields only `/audit/`, `/security/`, `/identity-providers/`, `/settings/`
(no bare form), where `main`'s `admin.py` registered both `/audit/` and `/audit`. `base.html` emits
`href="{{ page.path }}"` (bare) and `legacy_redirects.py` 301s to bare paths, so
`GET /admin/audit` is now three hops: 301 to `/audit`, implicit 307 to `/audit/`, 303 to
`/audit/events`. `tests/routers/test_admin.py::test_section_index_works_without_trailing_slash`
was deleted; only `/directory/requests` kept an equivalent (`test_directory.py:57`).

**Suggested fix:** Register both forms as `directory.py:62-70` and `integrations.py:73` already
do, and restore the bare-path test for each section.

**Files Affected:** `app/routers/audit.py`, `app/routers/security.py`,
`app/routers/identity_providers.py`, `app/routers/settings.py`, `app/routers/integrations.py`,
their tests

---

## [REVIEW] Degenerate single-tab third-level nav on user and group pages

**Discovered:** 2026-09-06 (nav-restructure branch, `/code-review`)
**Severity:** Low
**Found in:** `app/pages.py:133`, `app/templates/base.html:158`, `tests/test_pages.py:286-287`

Hiding `/users/new` and `/groups/new` from nav leaves `/users` and `/groups` with exactly one
visible child. `get_navigation_context('/users/list', 'admin')` and
`('/users/<id>/profile', 'admin')` both return `sub_sub_nav_items == ['/users/list']`;
`/groups/list` returns `['/groups/list']`. `base.html` has no single-item suppression, so a
full-width strip containing only "User List" (or "Group List") renders under the Directory sub-nav
on every user and group page. On `main` the list was empty for these paths. The existing test only
asserts membership, not that the strip is intentional.

**Suggested fix:** Either set `show_in_nav=False` on the lone list child (collapsing the level), or
have `get_navigation_context` / `base.html` suppress any level with fewer than two entries.

**Files Affected:** `app/pages.py` or `app/templates/base.html`, `tests/test_pages.py`

---

## [REVIEW] Hardcoded role tuple in `users_list.html` duplicates `pages.py`

**Discovered:** 2026-09-06 (nav-restructure branch, `/code-review`)
**Severity:** Low
**Found in:** `app/templates/users_list.html:96`, `app/pages.py:132,1024`,
`app/utils/templates.py`

The new Add User button is gated by `user.role in ('admin', 'super_admin')` inline in the template.
It is the only role-tuple gate in any template (`grep 'role in' app/templates`). `pages.py`, the
declared single source of truth for page access, already assigns `PagePermission.ADMIN` to
`/users/new`; if that changes or a role is added, the button and the route diverge silently.
`has_page_access(path, role)` exists in `pages.py` but is not a Jinja global (`templates.py`
registers only `static_url`, `icon`, `display_role`, `display_status`).

**Suggested fix:** Register `has_page_access` as a Jinja global and write
`{% if has_page_access('/users/new', user.role) %}`. Apply the same to Add Group and any other
action demoted from nav to a list-page button.

**Files Affected:** `app/utils/templates.py`, `app/templates/users_list.html`,
`app/templates/groups_list.html`

---

## [HOUSEKEEPING] Nav-restructure backlog item not archived

**Discovered:** 2026-09-06 (nav-restructure branch, `/code-review`)
**Severity:** Low
**Found in:** `.claude/BACKLOG.md:1042`

`.claude/ITERATION_nav_restructure.md:7` says "All 5 iterations complete. make quality-all green."
and the CHANGELOG entry exists, but `git diff main...HEAD -- .claude/BACKLOG.md
.claude/BACKLOG_ARCHIVE.md` is empty. The "Restructure Admin Navigation Around Concepts, Not
Permissions" item still sits in `BACKLOG.md` with every acceptance criterion unchecked. CLAUDE.md
rule 9 requires moving completed items to `BACKLOG_ARCHIVE.md` marked Complete.

**Suggested fix:** Archive the item. Note the deliberate deviation from the criterion at line 1117
(per-instance URLs 404 by design) so the archive entry is accurate, or resolve that deviation via
the catch-all redirect entry above first.

**Files Affected:** `.claude/BACKLOG.md`, `.claude/BACKLOG_ARCHIVE.md`

---

