# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## High Severity

(none)

---

## Medium Severity

### REFACT-002: service_providers.py exceeds 1100 lines (package split candidate)

**Found in:** `app/services/service_providers.py` (1129 lines, 26 functions)
**Severity:** Medium
**Category:** File Structure
**Description:** This module handles 5 distinct concerns: SP CRUD, SSO flow lookups, IdP metadata generation, per-SP signing certificates, and group assignments. It has grown to 1129 lines with 26 functions. Seven functions exceed 50 lines.
**Evidence:** 1129 lines, largest file in `app/services/` by nearly 2x. Contains duplicate code between `import_sp_from_metadata_xml` and `import_sp_from_metadata_url` (lines 249-322 vs 325-408), and between `get_tenant_idp_metadata_xml` and `get_sp_idp_metadata_xml` (lines 604-634 vs 637-679).
**Impact:** Hard to navigate in a single context window. Duplication increases risk of divergence when one copy is updated but not the other.
**Suggested fix:** Split into `app/services/service_providers/` package with submodules: `crud.py`, `sso.py`, `metadata.py`, `signing_certs.py`, `group_assignments.py`. Extract common metadata import logic into a shared helper.

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 1 | File Structure |
| Low | 0 | - |

**Last compliance scan:** 2026-02-12 (ARCH-001 and LOG-001 resolved)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---
