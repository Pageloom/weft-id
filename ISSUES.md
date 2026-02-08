# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Bug |
| Medium | 0 | - |
| Low | 0 | - |

**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## BUG: Users assigned to an IdP are not added to its base group

**Severity:** High
**Category:** Bug
**Found by:** Manual report
**Date:** 2026-02-08

**Description:**
Each IdP has an automatically created base/umbrella group (created in `create_identity_provider()` via `create_idp_base_group()`) that should contain all users assigned to that IdP. IdP-reported groups from SAML assertions become sub-groups of this base group. However, no assignment path actually adds users to the base group.

**Affected assignment paths (none add users to the base group):**

1. **JIT provisioning** (`app/services/saml/provisioning.py`)
   - `jit_provision_user()` creates user and sets `saml_idp_id`, but does not add to base group
   - `authenticate_via_saml()` only syncs assertion sub-groups (lines 175-184, 222-235), gated on `saml_result.groups`

2. **Privileged domain binding** (`app/services/saml/domains.py`)
   - `bind_domain_to_idp()` bulk-assigns users via `bulk_assign_users_to_idp()` (line 125), but does not add them to base group
   - `rebind_domain_to_idp()` moves users between IdPs (line 311), but does not update group membership

3. **Manual individual assignment** (`app/services/saml/domains.py`)
   - `assign_user_idp()` sets user's `saml_idp_id` (line 475), but does not add to base group

**Current behavior:**
- Users assigned to an IdP through any of the three paths above are never added to the IdP's base group
- Only IdP sub-groups from SAML assertion claims are synced (and only during SAML authentication)
- If the assertion has no group claims, the user ends up in zero IdP groups
- Even with group claims, users are only placed in the named sub-groups, never in the base group
- The UI, docstrings, and backlog archive all incorrectly claim this works:
  - `groups_detail.html:126` says "membership are managed by the identity provider"
  - `app/services/groups/idp.py:37` docstring says "All users authenticating via this IdP will be added to this group"
  - `app/services/groups/idp.py:66` sets group description to "All users authenticating via {idp_name}"
  - `BACKLOG_ARCHIVE.md:141` marks "All users authenticating via that IdP are automatically added to this group" as complete

**Expected behavior:**
- Every user assigned to an IdP (by any path) should be a member of that IdP's base group
- IdP-reported groups become sub-groups of the base group, and users should also be added to those as applicable
- When a user is moved between IdPs (rebind or reassignment), they should be removed from the old base group and added to the new one

**Fix approach:**
Add an `ensure_user_in_base_group(tenant_id, user_id, idp_id)` helper in `app/services/groups/idp.py` that:
1. Looks up the base group for the IdP (the group with matching `idp_id` that has no parent IdP group, or is flagged as the base)
2. Adds the user as a member if not already present
3. Call this helper from all three assignment paths
4. For rebind/reassignment, also remove user from the old IdP's base group

---
