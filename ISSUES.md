# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 5 | database integration test gaps (5) |
| Low | 0 | |

**Last security scan:** 2026-02-21 (SAML IdP focused assessment, 3 issues; 30-day incremental assessment, 2 new issues)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## [TEST] Integration tests for database/service_providers.py (41% coverage)

**Found in:** `app/database/service_providers.py`, no existing test file
**Severity:** Medium
**Description:** 9 functions with no integration tests. This module handles the full CRUD lifecycle for downstream SAML service providers, including trust establishment and metadata refresh. The SQL includes JSONB serialization (`json.dumps` for `attribute_mapping` and `sp_requested_attributes`) and conditional updates (`WHERE trust_established = false`).
**Untested functions:**
- `list_service_providers()` - basic listing
- `get_service_provider()` - by ID
- `get_service_provider_by_entity_id()` - by entity_id
- `create_service_provider()` - INSERT with JSONB fields
- `update_service_provider()` - dynamic SET clause from kwargs, JSONB serialization
- `set_service_provider_enabled()` - toggle via update
- `refresh_sp_metadata_fields()` - partial update of metadata-derived fields
- `establish_trust()` - conditional update (`WHERE trust_established = false`)
- `delete_service_provider()` - DELETE

**What to test:** Full CRUD lifecycle (create, read, update, delete). Verify JSONB fields round-trip correctly. Test `establish_trust` only works when `trust_established = false` and is a no-op when already established. Test `update_service_provider` ignores disallowed fields. Test `refresh_sp_metadata_fields` updates only metadata fields.
**Test file:** Create `tests/database/test_service_providers.py`

---

## [TEST] Integration tests for database/sp_group_assignments.py (32% coverage)

**Found in:** `app/database/sp_group_assignments.py`, no existing test file
**Severity:** Medium
**Description:** 9 functions with no integration tests. This module handles SP-to-group access control, including hierarchical access checks using the `group_lineage` closure table. The `user_can_access_sp()` and `get_accessible_sps_for_user()` queries join across 3-4 tables (`group_memberships`, `group_lineage`, `sp_group_assignments`, `service_providers`). These are critical authorization queries that should be validated against the real schema.
**Untested functions:**
- `list_assignments_for_sp()` - JOIN with groups
- `list_assignments_for_group()` - JOIN with service_providers
- `create_assignment()` - INSERT with RETURNING
- `delete_assignment()` - DELETE by composite key
- `bulk_create_assignments()` - dynamic VALUES clause with ON CONFLICT DO NOTHING
- `user_can_access_sp()` - 3-table JOIN using closure table for hierarchical access
- `get_accessible_sps_for_user()` - 4-table JOIN, filters on `enabled` and `trust_established`
- `count_assignments_for_sp()` - simple count
- `count_assignments_for_sps()` - aggregate counts returned as dict

**What to test:** Create a group hierarchy (parent > child), assign SP to parent group, add user to child group. Verify `user_can_access_sp()` returns True (inherited access via lineage). Verify `get_accessible_sps_for_user()` returns the SP. Verify direct membership also works. Test `bulk_create_assignments` with duplicate handling. Test that disabled/untrusted SPs are excluded from `get_accessible_sps_for_user`.
**Test file:** Create `tests/database/test_sp_group_assignments.py`
**Fixture dependencies:** Requires `test_tenant`, `test_user`, a group, a service provider, and group lineage rows.

---

## [TEST] Integration tests for database/users/saml_assignment.py (67% coverage)

**Found in:** `app/database/users/saml_assignment.py`, `tests/database/test_users.py`
**Severity:** Medium
**Description:** 7 of 8 functions have no integration tests. This module handles user-to-IdP assignment, password wiping, email unverification, and bulk domain binding operations. The bulk operations use `ANY(:user_ids)` array syntax. The `get_user_auth_info()` query is used by the email-first login flow to determine authentication routing, making it security-critical.
**Untested functions:**
- `get_user_auth_info()` - JOIN users + user_emails, returns auth routing info (has_password, saml_idp_id, is_inactivated)
- `wipe_user_password()` - sets password_hash to null
- `unverify_user_emails()` - sets verified_at to null, increments verify_nonce
- `get_users_by_email_domain()` - LIKE query with domain pattern
- `bulk_assign_users_to_idp()` - UPDATE with `ANY(:user_ids)` array
- `bulk_inactivate_users()` - UPDATE setting is_inactivated + clearing saml_idp_id
- `bulk_unverify_emails()` - UPDATE user_emails for multiple users

**What to test:** Create users with passwords and verified emails. Test `get_user_auth_info` returns correct has_password/saml_idp_id. Test `wipe_user_password` actually nulls the hash. Test `unverify_user_emails` clears verified_at and bumps nonce. Test bulk operations affect the right rows and respect empty-list guard. Create users with domain emails, verify `get_users_by_email_domain` finds them.
**Test file:** Add tests to existing `tests/database/test_users.py`
**Fixture dependencies:** Needs a SAML IdP record (requires `saml_idp_configs` table row).

---

## [TEST] Integration tests for SAML certificate modules (57%/58% coverage)

**Found in:** `app/database/saml/idp_certificates.py` (57%), `app/database/sp_signing_certificates.py` (58%)
**Severity:** Medium
**Description:** Both certificate modules have roughly half their functions untested. These handle certificate lifecycle (create, read, rotate, cleanup, delete) for both IdP certificates and per-SP signing certificates. The rotation logic in `sp_signing_certificates.py` moves the current cert to `previous_*` columns and sets grace period fields, which is important to validate against the real schema.

**Untested in `idp_certificates.py`** (3 of 6):
- `get_idp_certificate()` - by cert ID
- `get_idp_certificate_by_fingerprint()` - duplicate detection
- `delete_idp_certificate()` - DELETE returning bool
- `update_idp_certificate_fingerprint()` - backfill migration helper

**Untested in `sp_signing_certificates.py`** (3 of 5):
- `create_signing_certificate()` - INSERT with encrypted private key
- `rotate_signing_certificate()` - UPDATE moving current to previous_* columns
- `clear_previous_signing_certificate()` - cleanup after grace period

**What to test:** For IdP certs: create, retrieve by ID and fingerprint, delete. For SP signing certs: create, rotate (verify previous_* columns populated), clear previous (verify nulled). Both modules need a SAML IdP record and/or a service provider as fixtures.
**Test file:** Create `tests/database/test_certificates.py` covering both modules
**Fixture dependencies:** Needs a SAML IdP config row and a service provider row.

---

## [TEST] Integration tests for small database modules (40%/60%/67% coverage)

**Found in:** `app/database/sp_nameid_mappings.py` (40%), `app/database/saml/security.py` (60%), `app/database/groups/selection.py` (67%)
**Severity:** Medium
**Description:** Three small modules each have 1-3 untested functions. Grouped together because each is too small for a standalone issue but the SQL should still be validated.

**Untested in `sp_nameid_mappings.py`** (1 of 2):
- `get_or_create_nameid_mapping()` - INSERT ON CONFLICT DO NOTHING + SELECT for race safety. Generates a UUID NameID value. Important to verify the upsert pattern works against the real unique constraint.

**Untested in `saml/security.py`** (2 of 4):
- `count_users_without_idp_in_domain()` - JOIN users + user_emails with LIKE pattern, filters on verified_at and saml_idp_id IS NULL
- `count_users_with_idp_in_domain()` - same pattern but filters on specific idp_id

**Untested in `groups/selection.py`** (1 of 3):
- `get_groups_for_user_select()` - lists groups excluding those a user already belongs to (NOT EXISTS subquery)

**What to test:** For nameid mappings: create a mapping, verify get returns it, call get_or_create again for same pair, verify same mapping returned (idempotent). For security counts: create users with domain emails, some with IdP, some without, verify counts are correct. For selection: create groups, add user to one, verify the other appears in the select list.
**Test file:** Create `tests/database/test_sp_nameid_mappings.py` and add to existing `tests/database/test_groups.py` and `tests/database/test_security.py`

---

---
