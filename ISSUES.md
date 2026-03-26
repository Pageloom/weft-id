# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 2 | File Structure, Authentication |
| Low | 1 | Duplication |

**Last security scan:** 2026-03-21 (deep: full codebase, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-21 (password templates, API/service errors, self-hosting docs)
**Last security scan:** 2026-03-21 (weftid management script PR review, 3 issues found and resolved)

---

## [SECURITY] Set-password link lacks one-time nonce and expiry

**Found in:** `app/routers/auth/onboarding.py:78-129`
**Impact:** Medium
**Category:** Authentication / Token Security

**Description:**
The `/set-password?email_id=X` link used during user onboarding contains no secret nonce and has
no expiry. Its only protection is that it checks `user.get("password_hash") is None` (line 102).
This means:

1. **No secret in the URL**: The link contains only the `email_id` UUID. Anyone who obtains the
   URL (browser history, email forwarding, email server logs) can use it before the user does.
2. **No expiry**: The link is valid indefinitely until the user sets a password.
3. **Reusable if hash is cleared**: If a future admin flow (e.g. forced password reset) clears
   the `password_hash`, the original invitation link from the user's inbox becomes valid again.

The same issue applies to the privileged-domain invitation path where the auto-verified email
produces a set-password link with no nonce (`send_new_user_privileged_domain_notification`).

**Why It Matters:**
Password-setting links are high-privilege. Industry standard is time-limited, single-use tokens.
The `verify_nonce` mechanism already exists on `user_emails` for email verification; the same
approach should be applied to set-password links.

**Fix:**
Add a `set_password_nonce` column to `user_emails` (integer, default 1). Include the nonce in
all set-password URLs. Validate it in the GET and POST handlers. Increment it on successful use
and on invitation resend. See the BACKLOG item "Invitation and Set-Password Link Security
Hardening" for full acceptance criteria.

**Files Affected:** `app/routers/auth/onboarding.py`, `app/database/user_emails.py`,
`app/utils/email.py` (privileged domain invitation), migration required

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

