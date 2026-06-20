# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Test coverage (E2E anchor, deferred) |
| Deps | 2 | starlette (HIGH, FastAPI-compat eval needed), pygments (LOW, blocked by upstream) |

Note: the six inbound-SCIM final-review items (cross-IdP rebind audit event, actor
consistency, private-helper import boundary, `list_active_tokens` dead code, canonical-email
validation, Pydantic `max_length`) plus the project-wide proxy-headers / forwarded-host trust
boundary were resolved on the inbound-scim branch (2026-05-29); see ISSUES_ARCHIVE.md.

**Last security scan:** 2026-05-15 (mirror-failure audit event + user_profile_updated PII redaction landed on feature/user-attributes; remaining low items unchanged)
**Last compliance scan:** 2026-04-13 (all clear, 15 checks; re-verified during security/april-2026-sweep branch)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-06-20 (cryptography 48.0.0→48.0.1, python-multipart 0.0.29→0.0.31, pip 26.1.1→26.1.2, msgpack 1.1.2→1.2.1 bumped, clearing 4 HIGH CVEs; starlette HIGH deferred for FastAPI-compat eval, pygments still pinned `<2.20`, see [DEPS] entries below)
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

## [TEST] Regression anchor for user_attributes feature (E2E, deferred)

**Discovered:** 2026-05-14 (test agent final-pass review)
**Severity:** Low (deferred regression coverage)
**Source:** Test review (M-test1 + L bundle)

Five of the six original anchors landed on feature/forward-auth-proxy (2026-06-16);
see ISSUES_ARCHIVE.md. One remains, deferred because it needs Playwright + Docker:

- E2E for admin → user fills → SP receives (full cross-iteration journey)

**Files Affected:** `tests/e2e/`

---

## [DEPS] starlette 1.0.1 — 4 CVEs (HIGH, FastAPI-compat eval needed)

**Discovered:** 2026-06-20
**Severity:** High (2 HIGH, 1 MEDIUM, 1 LOW)
**Source:** `python dev/deps_check.py`

- **CVE-2026-48818** (GHSA-wqp7-x3pw-xc5r, HIGH) — fixed in 1.1.0
- **CVE-2026-54283** (HIGH) — fixed in 1.3.1
- **CVE-2026-48817** (GHSA-x746-7m8f-x49c, MEDIUM): `HTTPEndpoint` method
  lookup via unrestricted `getattr` — fixed in 1.1.0
- **CVE-2026-54282** (GHSA-jp82-jpqv-5vv3, LOW): `request.url` rebuilt from an
  unvalidated path — fixed in 1.3.0

**Remediation: DEFERRED (separate task).** Clearing the HIGHs needs starlette
≥1.3.1, but `fastapi >=0.135.2,<0.137.0` constrains the starlette range, so the
bump risks a FastAPI-compat break and needs its own verification pass (the
2026-06-20 audit bumped the low-risk deps in isolation per request). Bump
starlette together with a compatible FastAPI, then run the full suite.

**Files Affected:** `pyproject.toml`, `poetry.lock`

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
