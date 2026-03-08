# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 2 | Copy |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-03-05 (1 medium: incomplete API docstring)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-08 (full template scan, 7 direct fixes, 2 cross-file issues logged)

---

## [COPY] "Login" vs "Sign in" inconsistency in navigation labels

**Found in:** `app/templates/account_inactivated.html:56`, `app/templates/reactivation_requested.html:31`, `app/templates/super_admin_reactivate.html:49`, `app/templates/saml_error.html:75`, `app/templates/saml_idp_sso_error.html:82`, `app/templates/dashboard.html:31`, `app/templates/user_detail_tab_profile.html:52`, `app/templates/settings_profile.html:122`, `app/pages.py:48`
**Severity:** Low
**Description:** The project glossary prefers "Sign in / Sign out" over "Log in / Log out". Flash messages (verb form) have been fixed. However, the noun/label form "Login" remains in link text ("Back to Login", "Return to Login") and data labels ("Last Login"). The pages.py page title also uses "Login".
**Current:** "Back to Login", "Return to Login", "Last Login"
**Suggested:** "Back to sign in", "Return to sign in", "Last sign-in"
**Scope:** 8+ template locations plus `app/pages.py` page title. Consistent change needed across all.

---

## [COPY] "log in" in email template strings (Python code)

**Found in:** `app/utils/email.py:340`, `app/utils/email.py:368`
**Severity:** Low
**Description:** The welcome/password-set email body uses "log in" as a verb, inconsistent with the "sign in" terminology used in templates.
**Current:** "After setting your password, you'll be able to log in and access your account."
**Suggested:** "After setting your password, you'll be able to sign in and access your account."
**Scope:** 2 lines in `app/utils/email.py` (plain text and HTML versions of the same email).

---


