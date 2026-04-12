# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 2 | SSRF redirect-follow, unbounded admin forms |
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Duplication (pre-existing) |

**Last security scan:** 2026-04-12 (broad: all code from last 60 days, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-09 (GCM encryption feature, SAML error page, role display audit)

---

## [SECURITY] SSRF via HTTP Redirect Following in Metadata Fetch

**Found in:** `app/utils/url_safety.py:170-174`
**Severity:** Low
**OWASP Category:** A10:2021 - Server-Side Request Forgery
**Description:** The `validate_metadata_url()` function resolves the hostname and checks against IP blocklists before the request. However, `urllib.request.urlopen` follows HTTP 3xx redirects by default (up to 10 hops). A redirect to a blocked IP (e.g., `169.254.169.254`) happens after the initial validation, bypassing the SSRF protection (TOCTOU).
**Attack Scenario:** A super admin configures a metadata URL pointing to their server. That server responds with `302 Location: http://169.254.169.254/latest/meta-data/`. Python follows the redirect without re-validating the destination IP. In cloud deployments, this could hit the instance metadata service. AWS IMDSv2 mitigates (requires PUT), but IMDSv1 and other clouds may be vulnerable.
**Evidence:**
```python
validate_metadata_url(url)  # Validates original hostname only
# ...
with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:
    # urllib follows redirects to unvalidated destinations
```
**Impact:** Internal network scanning or cloud metadata exfiltration. Requires super admin access to trigger.
**Remediation:** Disable redirect following by installing a custom opener/handler that either blocks redirects entirely or re-validates each redirect destination against the IP blocklist before following.

---

## [SECURITY] Unbounded Form Parameters in Admin Web Forms

**Found in:** `app/routers/saml/admin/providers.py`, `app/routers/saml_idp/admin.py` (multiple routes)
**Severity:** Low
**OWASP Category:** Unbounded Input
**Description:** Admin web form routes accept `Form()` parameters (name, metadata_url, metadata_xml, entity_id, sso_url, certificate_pem, etc.) without `max_length` constraints at the HTTP layer. Pydantic schemas downstream DO have `max_length`, but the full request body is read into memory before validation.
**Impact:** Minimal. Requires super admin access. Pydantic catches oversized values downstream. Defense-in-depth concern only.
**Remediation:** Add `max_length` to Form() parameters matching the downstream Pydantic limits. Priority is low since exploitation requires authenticated super admin access.

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

