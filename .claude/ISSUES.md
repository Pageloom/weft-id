# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low | 5 | Duplication (pre-existing), Security hardening (new), Test coverage (new) |
| Deps | 1 | pygments (LOW, blocked by upstream) |

**Last security scan:** 2026-04-24 (targeted: all code from last 14 days, all OWASP categories; 3 findings, all resolved)
**Last compliance scan:** 2026-04-13 (all clear, 15 checks; re-verified during security/april-2026-sweep branch)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-05-15 (python-multipart, urllib3, pip bumped; pygments still pinned `<2.20`, see [DEPS] entry below)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-24 (terminology sweep: "two-step verification" → "sign-in strength" / "sign-in methods" where passkeys make "two-step" inaccurate)

---

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

---

## [REFACTOR] Duplication: Tab route pattern repeated 6x in saml_idp/admin.py

**Found in:** `app/routers/saml_idp/admin.py:225-436`
**Impact:** Low
**Category:** Duplication
**Description:** Six tab routes (sp_tab_details, sp_tab_attributes, sp_tab_groups, sp_tab_certificates, sp_tab_metadata, sp_tab_danger) follow an identical pattern: call `_load_sp_common()`, handle errors, build tab-specific context, return template response. The file is at 1089 lines with 33 route handlers.
**Why It Matters:** The repetitive pattern adds bulk, but the file is well-organized with clear section headers. This is low priority because each handler is compact (30-50 lines) and the structure is consistent.
**Accepted:** Each tab has genuinely different context loading logic. A generic helper would need callbacks that add complexity without improving readability. Monitor for further growth.
**Files Affected:** `app/routers/saml_idp/admin.py`

---


## [SECURITY] Hardening: structured event log for IdP mirror failures

**Discovered:** 2026-05-14 (security agent final-pass review L1)
**Severity:** Low
**Source:** Security review L1

`_apply_idp_attributes_safe` in `app/services/saml/provisioning.py` catches `Exception` broadly so SAML login never fails on mirror-write errors. Today it only emits `logger.warning`. A recurring failure would never reach the admin audit UI. Add a `user_idp_attribute_mirror_failed` event log entry (system actor) so the failure is surfaced as part of the standard audit stream.

**Files Affected:** `app/services/saml/provisioning.py`, `app/constants/event_types.py`, `app/constants/event_types.lock`

---

## [SECURITY] PII spillover in user_profile_updated event metadata

**Discovered:** 2026-05-14 (security agent final-pass review L2)
**Severity:** Low (compliance / data export consideration)
**Source:** Security review L2

The `user_profile_updated` events emit raw attribute values in metadata `changes` dict, including phone, mobile, street address, postal code, and employee ID. By design for audit traceability, but worth a follow-up review for event-log exports (PII redaction filter, sensitive-value hash, or category tagging).

**Files Affected:** `app/services/users/attributes.py`, `app/services/event_log.py`, event-log export utilities

---

## [DOCS] API endpoint docstring claims "super_admin only" but service is relaxed

**Discovered:** 2026-05-14 (security agent final-pass review L3)
**Severity:** Low (cosmetic)
**Source:** Security review L3

`list_tenant_attribute_config` was deliberately relaxed to any authenticated user during iter 7 so the force-completion gate is escapable for non-admin users. The API endpoint `GET /api/v1/tenant/attribute-config` is still super-admin-gated at the router layer, but the service docstring previously documented "super_admin only." Verify and update docstring wording.

**Files Affected:** `app/services/settings/attributes.py`, `app/routers/api/v1/settings.py`

---

## [TEST] Regression anchors for user_attributes feature

**Discovered:** 2026-05-14 (test agent final-pass review)
**Severity:** Low (deferred regression coverage)
**Source:** Test review (M-test1 + L bundle)

Useful regression anchors, none are current bugs:

- E2E for admin → user fills → SP receives (full cross-iteration journey)
- `apply_idp_attributes` "overwrites user-set canonical value when mirror=on" explicit test
- `apply_idp_attributes` "preserves unrelated canonical rows" explicit test
- Dashboard banner empty-case test (`missing_required == []`)
- JIT-provisioned user mirror-failure path (sibling to existing existing-user test)
- Admin user-detail route integration test for `user_profile_updated` event emission

**Files Affected:** `tests/services/test_saml_attribute_ingestion.py`, `tests/services/test_user_attributes_service.py`, `tests/routers/test_auth.py`, `tests/routers/test_user_detail_profile.py`, `tests/e2e/`

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
