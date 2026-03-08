# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 6 | Copy, Structure |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-03-05 (1 medium: incomplete API docstring)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-08 (structural IA review, 2 direct fixes, 4 structural issues logged)

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

## [STRUCTURE] Dead template: groups_detail_tab_danger.html

**Found in:** `app/templates/groups_detail_tab_danger.html`
**Severity:** Low
**Description:** This template is not referenced by any router. The group detail base template (`groups_detail_base.html`) only renders a "Delete" tab that routes to `groups_detail_tab_delete.html`. The danger template contains nearly identical code to the delete template (with minor differences: no `max-w-2xl` wrapper, extra success/error message handling). It was edited during the previous copy review pass but is dead code.
**Action:** Delete `groups_detail_tab_danger.html`. It adds maintenance burden and confusion.
**Scope:** Single file deletion.

---

## [STRUCTURE] Branding global: single form spans two visual sections

**Found in:** `app/templates/settings_branding_global.html:27-103`
**Severity:** Low
**Description:** The "Site Title" and "Display Mode" sections each have their own H2 heading and border-t separator, suggesting they are independent sections. But they share a single `<form>` element (opened at line 27, closed at line 102). This creates misleading visual hierarchy: they look independent but submit together. The logo uploads below are separate forms. An admin editing the site title must also submit the display mode setting, and vice versa.
**Suggestion:** Either (a) split into two forms so each section submits independently, or (b) remove the second H2/border-t and present them as subsections under a single "Settings" heading to make the shared form boundary visible.
**Scope:** Template restructuring in `settings_branding_global.html`.

---

## [STRUCTURE] User profile tab: read-only info at same weight as edit sections

**Found in:** `app/templates/user_detail_tab_profile.html`
**Severity:** Low
**Description:** The profile tab contains five H2 sections (User Information, Edit Name, Edit Role, Authentication Method, Email Addresses) all separated by identical border-t dividers with no grouping. Read-only information (User Information: ID, role, timezone, locale, MFA status, created, last login) uses the same visual weight as editing forms. The section order does not follow a task-based flow. An admin editing a user typically wants to: (1) change their name or role, (2) manage authentication, (3) manage emails. The read-only summary grid is useful context but should feel subordinate to the actionable sections, not co-equal.
**Suggestion:** Consider visually distinguishing the read-only summary (e.g., lighter background, no H2, or positioned as a sidebar/header) from the edit sections. Group the edit forms more tightly. Alternatively, move the summary to a separate "Info" card above the edit sections rather than inline as the first of five peers.
**Scope:** Template restructuring in `user_detail_tab_profile.html`.

---

## [STRUCTURE] Branding global: logo requirements note buried at page bottom

**Found in:** `app/templates/settings_branding_global.html:221-226`
**Severity:** Low
**Description:** The blue info box stating logo requirements ("Logos must be square. PNG images must be at least 48x48 pixels. SVG images should have a square viewBox. Maximum file size is 256KB.") appears after all upload sections and the mandala generator. Users will encounter upload validation errors before scrolling to these requirements. The intro paragraph (line 20) mentions some requirements but omits the square viewBox and max file size details.
**Suggestion:** Move the requirements note above the first logo upload section, or consolidate all requirements into the intro paragraph so they are visible before the user attempts an upload.
**Scope:** Reorder content in `settings_branding_global.html`.

---


