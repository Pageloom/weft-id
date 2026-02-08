# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Security |
| Medium | 1 | API-First |
| Low | 0 | - |

**Last compliance scan:** 2026-02-08 (automated + manual five-principle review)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## SECURITY: SQL injection via string interpolation in bulk group insert

**Found in:** `app/database/groups/idp.py:143`
**Severity:** High
**Principle Violated:** Tenant Isolation (parameterized query safety)
**Found by:** Compliance agent (manual review)
**Date:** 2026-02-08

**Description:**
`bulk_add_user_to_groups()` builds SQL VALUES via f-string interpolation instead of parameterized queries. The `group_ids`, `tenant_id_value`, and `user_id` values are inserted directly into the SQL string using Python string formatting.

**Evidence:**
```python
# Line 143
values = ", ".join(f"('{tenant_id_value}', '{gid}', '{user_id}')" for gid in group_ids)
cur.execute(
    f"""
    insert into group_memberships (tenant_id, group_id, user_id)
    values {values}
    on conflict (group_id, user_id) do nothing
    """
)
```

**Impact:**
In practice, all current callers pass database-generated UUIDs (from `_apply_membership_additions` in `app/services/groups/idp.py:179`), so the immediate exploitation risk is low. However, the pattern violates parameterized query safety and would become dangerous if any future caller passes user-controlled input.

**Root Cause:** Bulk insert optimization used string formatting instead of parameterized approach.

**Suggested fix:**
Replace with a parameterized loop or PostgreSQL UNNEST:
```python
for group_id in group_ids:
    cur.execute(
        """
        insert into group_memberships (tenant_id, group_id, user_id)
        values (%(tenant_id)s, %(group_id)s, %(user_id)s)
        on conflict (group_id, user_id) do nothing
        """,
        {"tenant_id": tenant_id_value, "group_id": group_id, "user_id": user_id},
    )
```

---

## API-FIRST: Missing API endpoint for user-IdP assignment

**Found in:** `app/routers/users/detail.py:181`
**Severity:** Medium
**Principle Violated:** API-First
**Found by:** Compliance agent (manual review)
**Date:** 2026-02-08

**Description:**
The web route `POST /users/{user_id}/update-idp` calls `saml_service.assign_user_idp()` to assign or unassign a user from an IdP. No corresponding REST API endpoint exists under `/api/v1/`.

**Evidence:**
- Web route: `app/routers/users/detail.py:181` (`POST /{user_id}/update-idp`)
- Service function: `saml_service.assign_user_idp()`
- API search: No matches for `assign_user_idp` or `update-idp` in `app/routers/api/v1/`

**Impact:**
API consumers cannot programmatically assign users to identity providers. This breaks the API-first principle for a significant admin operation (super_admin only).

**Root Cause:** The endpoint was added to the web router without a corresponding API endpoint.

**Suggested fix:**
Add a `POST /api/v1/users/{user_id}/idp` endpoint in `app/routers/api/v1/users/admin.py` (or a new `saml.py` API sub-file) that accepts `{"saml_idp_id": "..." | null}` and calls `saml_service.assign_user_idp()`.

---
