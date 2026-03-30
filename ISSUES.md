# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 3 | XSS, Unbounded Input, File Structure |
| Low | 2 | Logging, Duplication |

**Last security scan:** 2026-03-29 (deep: full codebase, all OWASP categories; 2 medium, 1 low)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-21 (password templates, API/service errors, self-hosting docs)

---

## [SECURITY] XSS: innerHTML with user-controlled names in bulk primary emails template

**Found in:** `app/templates/users_bulk_primary_emails.html:239, 294`
**Severity:** Medium
**OWASP Category:** A03:2021 - Injection (XSS)
**Description:** The bulk primary email change preview builds HTML via template literals using `${u.user_name}` and sets it via `innerHTML` (line 320: `previewResults.innerHTML = html`). User names come from `first_name`/`last_name` database fields which are user-controlled (max_length=255 but no HTML sanitization).
**Attack Scenario:** An admin creates a user with `first_name = '<img src=x onerror=alert(1)>'`. When another admin runs a bulk primary email preview that includes this user, the script executes in their browser (stored XSS, admin-to-admin).
**Evidence:**
```javascript
// Line 239 (error row) and 294 (success row):
<td ...>${u.user_name || u.user_id}</td>
// Line 320:
previewResults.innerHTML = html;
```
**Impact:** Stored XSS in admin context. Could steal session tokens or perform admin actions.
**Remediation:** Use DOM APIs with `textContent` instead of string interpolation with `innerHTML`. The groups_list.html graph tooltips already use the correct pattern (line 1038: `nameEl.textContent = node.data('label')`).

---

## [SECURITY] Unbounded Input: Bulk operation list fields missing max_length

**Found in:** `app/schemas/groups.py:312, 320, 328` and `app/schemas/service_providers.py:250`
**Severity:** Medium
**OWASP Category:** Unbounded Input / Resource Exhaustion
**Description:** Four Pydantic list fields accept unbounded arrays of UUIDs. Individual items have `max_length=36`, but the lists themselves have only `min_length=1` with no upper bound:
- `BulkMemberRemove.user_ids` (groups.py:312)
- `BulkMemberAdd.user_ids` (groups.py:320)
- `UserGroupsAdd.group_ids` (groups.py:328)
- `SPGroupBulkAssign.group_ids` (service_providers.py:250)
**Attack Scenario:** An authenticated admin sends a request with millions of UUIDs, causing memory/CPU exhaustion during Pydantic validation, service processing, and database queries.
**Impact:** Denial of service. Mitigated by requiring admin authentication, but still exploitable by any admin account.
**Remediation:** Add `max_length=1000` (or appropriate limit) to each list field. Example: `Field(..., min_length=1, max_length=1000)`.

---

## [SECURITY] Logging: Inconsistent authorization failure audit logging

**Found in:** `app/services/auth.py` (callers across services)
**Severity:** Low
**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures
**Description:** `require_admin()` and `require_super_admin()` accept an opt-in `log_failure=True` parameter that logs `authorization_denied` events. About half of the call sites pass this flag (SAML, service providers, users/crud, users/state, MFA), while the other half omit it (branding, groups, settings, exports, reactivation, bg_tasks). Authorization failures in the second group are silently raised without audit trail.
**Impact:** Incomplete visibility into unauthorized access attempts. The most security-sensitive operations (SAML, SPs, user management) are already logged, so the gap affects supporting services. Router-level auth dependencies catch most unauthorized access before reaching the service layer, further reducing risk.
**Remediation:** Either make `log_failure=True` the default in `require_admin()`/`require_super_admin()`, or add `log_failure=True, service_name="..."` to all remaining call sites.

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

