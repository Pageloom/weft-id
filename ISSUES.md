# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 6 | API-First (Documentation) |
| Low | 0 | |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-03-05 (1 medium: incomplete API docstring)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## API-First: Incomplete PATCH/PUT endpoint docstrings (6 endpoints)

**Severity:** Medium
**Principle Violated:** API-First (Documentation)
**Description:** PATCH/PUT endpoint docstrings do not document all accepted fields from their schemas. The new `--check api-first` scanner catches these automatically.
**Impact:** API consumers cannot discover all supported fields from endpoint documentation.
**Root Cause:** Docstrings were not updated as new fields were added to schemas over time.

**Affected endpoints:**

| Endpoint | Schema | Missing fields |
|----------|--------|----------------|
| `api/v1/service_providers.py:182` | SPUpdate (8 fields) | slo_url, nameid_format, include_group_claims, available_to_all, attribute_mapping |
| `api/v1/branding.py:85` | BrandingSettingsUpdate (5 fields) | use_logo_as_favicon, site_title, show_title_in_nav, group_avatar_style |
| `api/v1/settings.py:125` | TenantSecuritySettingsUpdate (7 fields) | inactivity_threshold_days, max_certificate_lifetime_years, certificate_rotation_window_days |
| `api/v1/groups.py:148` | GroupGraphLayout (2 fields) | node_ids, positions |
| `api/v1/groups.py:191` | GroupUpdate (2 fields) | name, description |
| `api/v1/users/profile.py:54` | UserProfileUpdate (5 fields) | theme |

**Suggested fix:** Update each endpoint's docstring to list all fields from its schema.

