# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## High Severity

### ISSUE-002: Group audit events silently lost due to invalid UUID in artifact_id

**Category:** Data Integrity Bug
**Found:** 2026-02-09
**Files:**
- `app/services/groups/idp.py` (lines 198, 247, 419, 452, 504, 545, 579)
- `app/services/groups/membership.py` (lines 121, 172)
- `app/services/groups/hierarchy.py` (lines 156, 204)

**Problem:** 11 `log_event()` calls pass `artifact_id=f"{id1}:{id2}"` (e.g. `f"{group_id}:{user_id}"`), but `event_logs.artifact_id` is a `UUID` column. The colon-separated string fails Postgres UUID validation, so the INSERT is rejected and the event is never recorded.

**Impact:** All audit events for group membership changes (add/remove member), IdP group sync operations, and group hierarchy changes (add/remove relationship) are silently discarded. This is a complete gap in the audit trail for the entire groups feature.

**Root cause:** The groups service was written to encode a composite key (group+user or parent+child) into `artifact_id`, but the column type is `UUID NOT NULL` and cannot hold compound values.

**Suggested fix:** Use one ID as `artifact_id` (e.g. the group ID) and move the second ID into the `metadata` dict. For example:
```python
log_event(
    artifact_id=group_id,
    metadata={"user_id": str(user_id)},
    ...
)
```

---

## Medium Severity

### ISSUE-001: Email MFA code not auto-sent on IDP/SAML sign-in

**Category:** UX Bug
**Found:** 2026-02-08
**File:** `app/routers/saml/authentication.py:302-308`

**Problem:** When a user signs in via SAML/IDP and has email-based MFA enabled, no verification email is sent automatically. The user lands on `/mfa/verify` with an empty inbox and must manually click "Send code to my email."

**Root cause:** The SAML ACS handler stores pending MFA session data and redirects to `/mfa/verify` but does not call `create_email_otp()` or `send_mfa_code_email()`. The password login flow (`app/routers/auth/login.py:495-501`) does auto-send.

**Fix:** Add email OTP creation and sending logic to the SAML MFA block in `authentication.py`, matching the password login behavior. Requires importing `create_email_otp`, `send_mfa_code_email`, and `emails_service`.

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Data Integrity Bug |
| Medium | 1 | UX Bug |
| Low | 0 | - |

**Last compliance scan:** 2026-02-08 (automated + manual five-principle review)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---
