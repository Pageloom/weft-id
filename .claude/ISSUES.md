# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Duplication (pre-existing) |
| Low | 1 | Copy |

**Last security scan:** 2026-04-13 (broad: all code from last 90 days, all OWASP categories; 2 findings, both fixed)
**Last compliance scan:** 2026-04-13 (all clear, 15 checks; re-verified during security/april-2026-sweep branch)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-23 (7 passkey-related copy issues fixed across templates and emails)

---

---

## [COPY] "two-step verification" wording on Authentication settings page is inaccurate once passkeys exist

**Found in:** `app/templates/settings_security_tab_authentication.html`
**Severity:** Low
**Description:** The tenant auth strength setting is labelled "Minimum two-step verification strength" with help text "Controls which two-step methods are acceptable for sign-in." A passkey sign-in is a single cryptographic step (the credential itself embodies possession plus user verification); under `enhanced` with a registered passkey the user signs in with the passkey alone, no password and no second factor. Calling the resulting policy "two-step verification" misrepresents that path.
**Evidence:** Three strings in `app/templates/settings_security_tab_authentication.html` (label on line ~15, help text on ~18, `<legend class="sr-only">` on ~24) use "two-step". Also indirectly affects related copy: the section name, any future docs, and the `enroll_enhanced_auth.html` page header ("Set up two-step verification" / equivalent) once the passkey option is added to that flow.
**Impact:** Misleads admins about what enhanced policy actually requires: the policy is about authentication *strength* (phishing resistance), not specifically a "two-step" flow. Once passkey login ships in iteration 3, "two-step verification" becomes factually wrong for passkey users.
**Suggested fix:** Rename to something like "Minimum authentication strength" / "Minimum sign-in strength" and reword help text in terms of sign-in methods, not steps. Needs a copy-style decision: the glossary currently uses "two-step verification" for TOTP + email OTP, so any change should be coordinated with `/tech-writer` to keep terminology consistent across emails, onboarding, and user guides (e.g., `docs/user-guide/two-step-verification/` route, `app/utils/email.py` subject lines).
**Deferred reason:** Intentionally deferred by user until after iteration 3 (passkey login) lands -- at that point the terminology shift is naturally motivated by new UX, and a single copy sweep can update the settings page, the enrollment page, emails, and docs together.

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

## [COPY] settings_mfa.html: page title "Two-Step Verification" mixed with passkey management

**Found in:** `app/templates/settings_mfa.html` line 8
**Severity:** Low
**Description:** Page titled "Two-Step Verification" manages passkeys too. Passkeys are a first-factor replacement, not a second step.
**Impact:** Terminology confusion; touches page title, doc filename (`docs/user-guide/two-step-verification.md`), and mkdocs nav.
**Suggested fix:** Consider "Sign-in Methods" or "Two-Step Verification and Passkeys". Coordinate across templates, emails, docs, glossary. Ties into existing deferred copy issue (["two-step verification" wording on Authentication settings page](#copy-two-step-verification-wording-on-authentication-settings-page-is-inaccurate-once-passkeys-exist)).

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

