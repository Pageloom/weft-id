# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | File Structure |
| Medium | 3 | File Structure, Duplication |
| Low | 1 | Duplication |

**Last security scan:** 2026-03-21 (deep: full codebase, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-21 (password templates, API/service errors, self-hosting docs)
**Last security scan:** 2026-03-21 (weftid management script PR review, 3 issues found and resolved)

---

## [REFACTOR] File Structure: settings.py is a god module at 1094 lines

**Found in:** `app/services/settings.py`
**Impact:** High
**Category:** File Structure
**Description:** This file handles two distinct concerns: privileged domain management (lines 37-551) and tenant security settings (lines 554-1094). The `update_security_settings()` function alone is 264 lines (lines 831-1094), combining validation, merge logic, database updates, and multi-event logging. The merge/resolve pattern repeats 9 times identically, and changes metadata building has 51 lines of repetitive if-blocks.
**Why It Matters:** At 1094 lines with 24 functions across 2 concerns, this file exceeds the critical threshold. The 264-line update function is the largest in the codebase and difficult to reason about.
**Suggested Refactoring:** Split into `app/services/settings/` package:
- `domains.py` (~350 lines): domain CRUD and group linking
- `security.py` (~350 lines): security settings with extracted helpers
- Extract `_merge_security_update(current, update) -> dict` for the repeated merge pattern
- Extract `_build_changes_metadata(current, updated) -> dict` for change tracking
**Files Affected:** `app/services/settings.py`, `app/routers/settings.py`, tests

---

## [REFACTOR] File Structure: groups/idp.py split candidate at 710 lines

**Found in:** `app/services/groups/idp.py`
**Impact:** Medium
**Category:** File Structure
**Description:** This file handles two distinct concerns: group creation/discovery (create_idp_base_group, get_or_create_idp_group, _ensure_umbrella_relationship, invalidate_idp_groups) and membership management (sync_user_idp_groups, ensure_user_in_base_group, remove_user_from_base_group, move_users_between_idps). At 710 lines with 15 public functions, it's at the limit of maintainability.
**Why It Matters:** The two concerns are intertwined but distinct. Splitting improves traversability and makes each module's purpose clear.
**Suggested Refactoring:** Split into two modules within the existing groups package:
- `idp_creation.py` (~350 lines): group lifecycle and discovery
- `idp_membership.py` (~350 lines): sync, base group membership, cross-IdP moves
**Files Affected:** `app/services/groups/idp.py`, `app/services/groups/__init__.py`, tests

---

## [REFACTOR] Duplication: Logo upload/delete duplicated between group and SP

**Found in:** `app/services/branding.py:555-697`
**Impact:** Medium
**Category:** Duplication
**Description:** `upload_group_logo()` (lines 555-588) and `upload_sp_logo()` (lines 630-663) are near-identical, differing only in the database method called. Same for `delete_group_logo()` (lines 591-622) and `delete_sp_logo()` (lines 666-697). This is ~60 lines of duplicated logic.
**Why It Matters:** Bug fixes or behavior changes must be applied in two places. The file is at 769 lines and growing.
**Suggested Refactoring:** Extract parameterized helpers:
- `_upload_logo_for_entity(entity_type, entity_id, data, content_type, ...)`
- `_delete_logo_for_entity(entity_type, entity_id, ...)`

```python
# Before (repeated twice):
def upload_group_logo(requesting_user, group_id, data, content_type):
    _require_admin(requesting_user)
    _validate_logo(data, content_type)
    db_branding.store_group_logo(tenant_id, group_id, data, content_type)
    log_event(...)

# After (single parameterized helper):
def _upload_logo(requesting_user, entity_type, entity_id, data, content_type, store_fn, event_type):
    _require_admin(requesting_user)
    _validate_logo(data, content_type)
    store_fn(requesting_user["tenant_id"], entity_id, data, content_type)
    log_event(..., event_type=event_type, artifact_type=entity_type, artifact_id=entity_id)
```
**Files Affected:** `app/services/branding.py`

---

## [REFACTOR] File Structure: routers/settings.py at 814 lines with mixed concerns

**Found in:** `app/routers/settings.py`
**Impact:** Medium
**Category:** File Structure
**Description:** This router has grown to 814 lines. It contains branding routes (lines 606-814, ~209 lines) that could be a separate router module. Additionally, form parsing validation for security settings is repeated 4 times (lines 362-412, 435-476, 498-539, 561-598) with identical parse-int/validate/catch-ValueError structure.
**Why It Matters:** The branding routes are conceptually separate from security/domain settings. The repeated form validation adds fragile boilerplate that should live in the service layer.
**Suggested Refactoring:**
- Extract branding routes to `app/routers/settings_branding.py` (reduces to ~600 lines)
- Move integer validation constraints to the service layer (aligns with API-first methodology)
**Files Affected:** `app/routers/settings.py`

---

## [REFACTOR] Duplication: Tab route pattern repeated 6x in saml_idp/admin.py

**Found in:** `app/routers/saml_idp/admin.py:225-436`
**Impact:** Low
**Category:** Duplication
**Description:** Six tab routes (sp_tab_details, sp_tab_attributes, sp_tab_groups, sp_tab_certificates, sp_tab_metadata, sp_tab_danger) follow an identical pattern: call `_load_sp_common()`, handle errors, build tab-specific context, return template response. The file is at 1089 lines with 33 route handlers.
**Why It Matters:** The repetitive pattern adds bulk, but the file is well-organized with clear section headers. This is low priority because each handler is compact (30-50 lines) and the structure is consistent.
**Suggested Refactoring:** A tab route factory or shared decorator could reduce boilerplate, but this is optional given the file's clear structure. Monitor for further growth.
**Files Affected:** `app/routers/saml_idp/admin.py`

---

