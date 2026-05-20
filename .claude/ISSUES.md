# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low | 3 | Duplication (pre-existing), Docs (pre-existing), Test coverage (pre-existing) |
| Deps | 2 | markdown (HIGH, blocked by upstream; blocks deps gate), pygments (LOW, blocked by upstream) |

**Last security scan:** 2026-05-15 (mirror-failure audit event + user_profile_updated PII redaction landed on feature/user-attributes; remaining low items unchanged)
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

## [SECURITY HIGH] Outbound SCIM worker: no row-level lock on queue ready-set scan

**Discovered:** 2026-05-20 (iter 7b fix-now triage; deferred for follow-up)
**Severity:** High
**Source:** Security review of `outbound-scim` branch

`database.scim_push_queue.list_ready_entries` and the cleared
`next_attempt_at` reset run under tenant RLS but use no row-level lock.
Running multiple worker containers (the documented horizontal-scale
story) means two workers can pick up the same queue row and double-push
to a downstream SP. The current per-tenant `with session(...)` loop in
`app/jobs/process_scim_push_queue.py` masks this in dev but not at scale.

**Suggested fix:** Add `FOR UPDATE SKIP LOCKED` to the
`list_ready_entries` query, or take a per-tenant advisory lock around
the drain loop. Either approach is bounded scope.

**Files affected:** `app/database/scim_push_queue.py`, possibly
`app/jobs/process_scim_push_queue.py`.

---

## [SECURITY MEDIUM] Bearer-token scrubbing in scim_sync_log.error

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Medium

A misbehaving downstream SP can echo the inbound `Authorization: Bearer
...` header in the 4xx/5xx response body. That body lands in
`scim_sync_log.error`, where it is rendered in the admin UI's Sync
activity panel and exported via the API. Bearer plaintext should never
leak back into our own logs.

**Suggested fix:** In each quirk module's `interpret_error`, scrub
`Authorization: Bearer ...` (and `Bearer\s+\S+`) before recording the
reason string. The base `interpret_error` is the natural home.

**Files affected:** `app/services/scim/quirks/*.py` (or a shared
sanitiser in `app/services/scim/client.py`).

---

## [SECURITY MEDIUM] scim_config_updated audit metadata stores raw old/new URL

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Medium

`services.scim.admin.update_scim_config` writes the previous and new
`scim_target_url` verbatim into the `scim_config_updated` audit event's
metadata. The renderer for that event in the audit log UI does not yet
escape user-controlled URLs, opening a log-injection / phishing surface
(a malicious super-admin could set a target URL that renders as a
clickable link to a phishing page).

**Suggested fix:** Either restrict what gets stored (record only the
hostname or a redacted form), or harden the audit-log renderer to
HTML-escape URL values consistently.

**Files affected:** `app/services/scim/admin.py`,
`app/templates/audit_event_detail.html`.

---

## [SECURITY LOW] Credential rotation TOCTOU

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Low

`services.scim.admin.rotate_credential` reads the active credentials,
mints a new row, then schedules the old one for revocation. Two
concurrent rotates against the same credential produce two new
credentials and double-schedule the old one for revocation. The blast
radius is small (an extra dangling token, not a security regression),
but the path should serialise via a SELECT ... FOR UPDATE or per-SP
advisory lock.

**Files affected:** `app/services/scim/admin.py`,
`app/database/scim_credentials.py`.

---

## [SECURITY LOW] No rate limit on POST /scim/credentials

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Low

A super-admin can spam `POST /api/v1/service-providers/{sp_id}/scim/credentials`
to mint unbounded credential rows. Operational rather than security risk
(the table is small and the role is highly privileged), but a sensible
defence-in-depth cap (e.g. 10/min/SP) would prevent runaway scripts.

**Files affected:** `app/routers/api/v1/service_providers.py`.

---

## [TEST MEDIUM] SCIM admin UI: rotate / revoke / retry-dead-lettered flows not in E2E

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Medium

`tests/e2e/test_scim_admin_e2e.py` covers create-token plaintext display
but not rotation, revoke, or the retry-dead-lettered button. Add three
short Playwright tests modelled on the existing create-token flow.

**Files affected:** `tests/e2e/test_scim_admin_e2e.py`.

---

## [TEST MEDIUM] Decrypt-failure path has no admin-UI signal

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Medium

`jobs.process_scim_push_queue._resolve_outbound_token` returns None
both when no credential ever existed AND when `InvalidToken` fires on
Fernet decryption (key rotation without a re-encrypt). The worker dead-
letters with the same `no_credential_source` reason in both cases, so
the admin UI cannot distinguish "configure a token" from "your key is
out of sync." Add a distinct reason string (e.g. `credential_decrypt_failed`)
and surface it in the sync-log panel.

**Files affected:** `app/jobs/process_scim_push_queue.py`,
`app/services/scim/worker.py`.

---

## [TEST MEDIUM] enqueue_sp_tenant_fan_out has no batching cap for large tenants

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Medium

For a tenant with 10k users, the SP enable / scope-change fan-out fires
10k queue upserts under the calling request's thread. The request still
returns quickly because each upsert is small, but the burst can starve
other DB work briefly. Either batch the upserts into a single INSERT
... SELECT, or off-load to a one-shot background task.

**Files affected:** `app/services/scim/dispatch.py` (or wherever
`enqueue_sp_tenant_fan_out` lives).

---

## [COMPLIANCE LOW] RLS widening on SCIM tables relies on developer discipline

**Discovered:** 2026-05-20 (iter 7b fix-now triage)
**Severity:** Low

Migration 0037 widened RLS on `scim_push_queue`, `scim_sync_log`, and
`sp_scim_credentials` so the worker can scan cross-tenant. The widening
is necessary but creates a footgun: any future code path that performs
an UNSCOPED read on those tables outside `app/jobs/` could leak across
tenants. The compliance check should grow a rule that flags `UNSCOPED`
reads of tenant-scoped tables when the call site is not under
`app/jobs/` or `app/services/scim/`.

**Files affected:** `dev/compliance_check.py`.

---

## [DOCS] SCIM admin guide MEDIUM tech-writer findings (W4-W10)

**Discovered:** 2026-05-20 (iter 7b fix-now triage; deferred per lead)
**Severity:** Medium (docs polish)

Tech-writer agent flagged seven medium-severity copy / structure issues
in `docs/admin-guide/service-providers/scim.md` (the W4-W10 items in the
iter-7 final-review notes). Defer to a documentation-only pass; none
block release.

**Files affected:** `docs/admin-guide/service-providers/scim.md`.

---

## [DEPS] markdown 3.10.2 -- PYSEC-2026-89 / CVE-2025-69534 (HIGH, blocked by upstream)

**Discovered:** 2026-05-20 (newly catalogued in GitHub Advisory DB; surfaced by `make check`)
**Severity:** High
**Source:** `python dev/deps_check.py`

**PYSEC-2026-89 (CVE-2025-69534):** Malformed HTML-like sequences cause
`html.parser.HTMLParser` to raise an unhandled `AssertionError` during
Markdown parsing. Any caller that does not catch `AssertionError` will
crash on attacker-controlled input.

**Exploitability in this project: NONE.** `markdown` is a transitive
dep of `zensical` and `pymdown-extensions`, used only by the docs site
build at Docker image-build time. Markdown is never parsed at request
time; the deployed site serves pre-built static HTML. No user-supplied
markdown is ever fed to the library.

**Remediation: BLOCKED.** `markdown` 3.10.2 is the latest release; no
upstream fix has shipped (advisory does not list a Fixed-in version as
of 2026-05-20). Pinning to an older version would not help; the issue
is present from 3.8 onward.

**Blocks `make check` deps gate** (deps_check exits 1 on any HIGH or
critical finding). Until upstream patches, every `make check` /
`make quality-all` run will fail at the dependency stage. Individual
stages (lint, format, types, compliance, tests, e2e) all pass.

Re-check periodically; bump as soon as a patched release lands.

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
