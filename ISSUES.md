# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## SAML authenticate_via_saml Uses Wrong Database Field Names

**Found in:** `app/services/saml.py:1072-1103`

**Severity:** High

**Description:** The `authenticate_via_saml` function calls `database.users.get_user_by_email()` but uses incorrect field names from the returned dict, causing a KeyError when a user attempts to sign in via SAML.

**Evidence:**
1. `database.users.get_user_by_email()` at line 38-47 returns: `user_id, password_hash`
2. `authenticate_via_saml()` at line 1083 checks: `user.get("inactivated_at")` - field doesn't exist
3. `authenticate_via_saml()` at line 1092-1094 uses: `user["id"]` - should be `user["user_id"]`

**Impact:**
- SAML sign-in flow completely broken
- Any user attempting SAML authentication gets a KeyError crash
- This is a critical authentication pathway

**Root Cause:** The `authenticate_via_saml` function was written expecting a full user record from the database, but `get_user_by_email` was designed for password authentication and only returns minimal fields (`user_id` and `password_hash`).

**Suggested fix:**

Option A (Recommended): Use a different database function that returns full user data:
```python
# Instead of:
user = database.users.get_user_by_email(tenant_id, email)

# Use (need to verify this function exists):
user = database.users.get_user_by_id_with_status(tenant_id, user_id)
```

Option B: Create a new database function specifically for SAML auth:
```python
# In app/database/users.py, add:
def get_user_for_saml_auth(tenant_id: TenantArg, email: str) -> dict | None:
    """Get full user record by verified email for SAML authentication."""
    return fetchone(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, u.inactivated_at, u.role
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email and ue.verified_at is not null
        """,
        {"email": email},
    )
```

Then update the service to use this function and fix the field name from `user_id` to `id`.

**Files to modify:**
- `app/database/users.py` - Add new function or modify existing
- `app/services/saml.py` - Update `authenticate_via_saml` to use correct function/fields

---

