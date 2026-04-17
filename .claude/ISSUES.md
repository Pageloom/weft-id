# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 2 | API-First |
| Low | 1 | API-First |
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Duplication (pre-existing) |
| Low | 1 | Copy |

**Last security scan:** 2026-04-13 (broad: all code from last 90 days, all OWASP categories; 2 findings, both fixed)
**Last compliance scan:** 2026-04-13 (all clear, 15 checks; re-verified during security/april-2026-sweep branch)
**Last API coverage audit:** 2026-04-13 (conceptual review: 3 gaps found across ~180 API endpoints)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-13 (security sweep templates, SAML IdP/SP, user profile, email audit)

---

## [API-FIRST] Missing API: Group clear all relationships

**Found in:** `app/routers/api/v1/groups.py`
**Severity:** Medium
**Principle Violated:** API-First
**Description:** The web UI exposes `POST /admin/groups/{group_id}/relationships/clear` which calls `groups_service.remove_all_relationships()`. The API has no equivalent. Consumers must enumerate and DELETE each parent/child relationship individually, with no atomicity.
**Evidence:** `remove_all_relationships()` is exported from `app/services/groups/__init__.py` (line 53) but never referenced in `app/routers/api/v1/groups.py`.
**Impact:** An API consumer reassigning a group's position in the hierarchy needs N calls instead of one, and partial failure leaves inconsistent state since individual deletes are not wrapped in a single transaction.
**Suggested fix:** Add `DELETE /api/v1/groups/{group_id}/relationships` that calls `groups_service.remove_all_relationships(requesting_user, group_id)`. Return 204 on success.

---

## [API-FIRST] Missing API: IdP reimport metadata from XML

**Found in:** `app/routers/api/v1/saml.py`
**Severity:** Medium
**Principle Violated:** API-First
**Description:** The web UI exposes `POST /admin/settings/identity-providers/{idp_id}/reimport-metadata` which accepts pasted XML, parses it via `saml_service.parse_idp_metadata_xml_to_schema()`, and updates the IdP's SSO URL, SLO URL, and certificate. The API has no equivalent for applying XML to an existing IdP. It only has `POST /idps/import-xml` (creates new), `POST /idps/{idp_id}/refresh` (URL-based), and `PATCH /idps/{idp_id}` (manual fields).
**Evidence:** `app/routers/saml/admin/providers.py:625-666` (web handler). No corresponding route in `app/routers/api/v1/saml.py`.
**Impact:** When an IdP rotates its certificate and doesn't expose a metadata URL, API consumers must parse SAML metadata themselves and PATCH individual fields. This is the primary recovery path for certificate rotation. B2B/automation clients are blocked without it.
**Suggested fix:** Add `POST /api/v1/idps/{idp_id}/reimport-xml` that accepts `metadata_xml` in the request body, parses it, and applies the extracted fields. Mirrors the web handler logic.

---

## [API-FIRST] Missing API: SAML debug log entries

**Found in:** `app/routers/api/v1/saml.py`
**Severity:** Low
**Principle Violated:** API-First
**Description:** The web UI exposes `GET /admin/audit/saml-debug` (list) and `GET /admin/audit/saml-debug/{entry_id}` (detail) via `app/routers/saml/admin/debug.py`. These call `saml_service.list_saml_debug_entries()` and `saml_service.get_saml_debug_entry()`. The API can toggle verbose logging on/off but provides no way to read the resulting entries.
**Evidence:** `app/routers/saml/admin/debug.py:23-72` (web handlers). No corresponding routes in `app/routers/api/v1/saml.py`.
**Impact:** B2B clients debugging SAML integration issues through the API must switch to the web UI to view failure details. Lower severity because this is primarily a setup-time concern, not ongoing operations.
**Suggested fix:** Add `GET /api/v1/idps/{idp_id}/debug-entries` (list, with limit parameter) and `GET /api/v1/idps/{idp_id}/debug-entries/{entry_id}` (detail). Alternatively, scope under a general audit path: `GET /api/v1/saml/debug-entries`.

---

## [COPY] email.py: generic MFA subject, "please" usage, "activate" terminology

**Found in:** `app/utils/email.py`
**Severity:** Low
**Description:** Three copy issues in outbound emails requiring Python code changes:

1. **Generic MFA subject (line 163):** Subject is "Your verification code" but should be "Your two-step verification code" to match the glossary. Heading on line 176 and body on line 177 also use generic "Verification Code" / "continue signing in" instead of mentioning two-step verification.

2. **"please" usage (~20 occurrences):** The copy style guide calls for terse, direct language. Phrases like "please ignore this email", "please verify your email", "please contact your administrator" should drop "please" (e.g., "If you did not request this code, ignore this email.").

3. **"activate" in invitation emails (lines 382, 398-399):** Invitation text says "activate your account" and the CTA button says "Activate Account". Per the glossary, "Activate" is not used for users. Clearer as "set up your account" / "Set Up Account".

**Scope:** ~25 string changes across one file. All in `app/utils/email.py`.

---

## [BUG] SAML IdP `require_platform_mfa` flag is not enforced

**Found in:** `app/routers/saml/authentication.py` (ACS endpoint)
**Severity:** Medium
**Description:** The `saml_identity_providers.require_platform_mfa` column exists in the schema and is configurable from the admin UI (`app/routers/saml/admin/providers.py:510`), but it has no effect at authentication time. After a successful SAML assertion, the user is signed in directly without any platform-side two-step verification, regardless of the flag's value.
**Evidence:** No reference to `require_platform_mfa` in the ACS processing chain in `app/routers/saml/authentication.py` or in `app/services/saml/` login paths. Admins who enable this flag expect to gate SAML users behind a WeftID-side MFA step; currently nothing happens.
**Impact:** Admins cannot enforce platform-side two-step verification for IdP-authenticated users. This is a silent failure: the UI accepts the setting and persists it, but authentication proceeds as if the flag were off.
**Suggested fix:** After successful SAML assertion processing in the ACS, if the chosen IdP has `require_platform_mfa=true`, stash pending-MFA state in the session and redirect the user to `/mfa/verify` before completing the login. The MFA step should accept the user's configured two-step method (email OTP, TOTP, or passkey once passkeys are available).

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

