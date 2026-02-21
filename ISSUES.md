# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 6 | database integration test gaps (6) |
| Low | 2 | SLO validation, cert cleanup race |

**Last security scan:** 2026-02-21 (SAML IdP focused assessment, 3 issues; 30-day incremental assessment, 2 new issues)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## [TEST] Integration tests for database/groups/memberships.py (28% coverage)

**Found in:** `app/database/groups/memberships.py`, `tests/database/test_groups.py`
**Severity:** Medium
**Description:** 5 of 12 functions have no integration tests. The untested functions build dynamic SQL with search tokenization, role/status filtering, and pagination. Their SQL is never executed against the real schema in tests.
**Untested functions:**
- `search_group_members()` - dynamic WHERE clauses, 6 sort fields, role/status filters, ILIKE search tokenization
- `count_group_members_filtered()` - matching filter logic for pagination counts
- `search_available_users()` - NOT EXISTS subquery excluding current members and service accounts
- `count_available_users()` - matching count query
- `bulk_remove_group_members()` - transactional multi-delete via `session()` context manager

**Already tested:** `get_group_members`, `count_group_members`, `is_group_member`, `add_group_member`, `remove_group_member`, `bulk_add_group_members`, `get_user_groups`
**What to test:** Create a group with several members (varying roles, statuses). Test each search/filter/sort combination against the real database. Verify `bulk_remove_group_members` atomicity (partial failure rolls back). Verify `search_available_users` correctly excludes existing members and OAuth2 service users.
**Test file:** Add tests to existing `tests/database/test_groups.py`

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

## [SECURITY] SLO LogoutRequest Processed Without Validation

**Found in:** `app/routers/saml_idp/slo.py:69-116` (`_handle_slo_request`)
**Severity:** Low
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** Two issues in the SLO flow combine to allow forced user logout:

1. **Session cleared before issuer validation** (line 88): The user's session is cleared immediately after parsing the LogoutRequest XML, before checking whether the issuer is a registered SP. Any syntactically valid LogoutRequest (even from an unregistered source) will destroy the user's session.

2. **No signature validation on LogoutRequests**: `parse_sp_logout_request()` parses the XML structure but does not validate the XML signature. Any party can forge a LogoutRequest.

**Attack Scenario:** An attacker crafts a minimal valid LogoutRequest (just needs an `<ID>` attribute and wrapping `<LogoutRequest>` element) and redirects a victim's browser to `/saml/idp/slo?SAMLRequest=<base64_encoded_forged_request>`. The victim's session is destroyed, forcing a re-login.
**Evidence:**
```python
# slo.py:77-88 - Session cleared unconditionally before issuer check
def _handle_slo_request(...):
    # 1. Parse the LogoutRequest
    try:
        parsed = parse_sp_logout_request(saml_request, binding)
    except ValueError as e:
        ...

    # 2. Clear the user's session (before any SP validation!)
    request.session.clear()

    # 3. Build LogoutResponse (this is where issuer is first checked)
    ...
    logout_response_b64, slo_url = process_sp_logout_request(...)
```
**Impact:** Forced user logout (denial of service). No data leakage or privilege escalation.
**Remediation:**
1. Move `request.session.clear()` after `process_sp_logout_request()` succeeds (after the issuer is validated as a registered SP)
2. Consider adding LogoutRequest signature validation using the SP's registered certificate

Example fix:
```python
def _handle_slo_request(...):
    try:
        parsed = parse_sp_logout_request(saml_request, binding)
    except ValueError as e:
        return RedirectResponse(url="/login", status_code=303)

    base_url = get_base_url(request)
    try:
        logout_response_b64, slo_url = process_sp_logout_request(
            tenant_id=tenant_id, parsed_request=parsed, base_url=base_url,
        )
    except Exception as e:
        return RedirectResponse(url="/login", status_code=303)

    # Only clear session after validating the request came from a registered SP
    request.session.clear()
    ...
```

---

## [SECURITY] Certificate Cleanup Race Condition

**Found in:** `app/jobs/rotate_certificates.py:278-316`, `app/database/sp_signing_certificates.py:160-181`
**Severity:** Low
**OWASP Category:** A04:2021 - Insecure Design
**Description:** The certificate cleanup job selects certificates whose `rotation_grace_period_ends_at < now()`, then issues an UPDATE to clear the previous certificate fields. The UPDATE does not re-verify that `rotation_grace_period_ends_at` still matches the value seen at selection time. If an admin manually rotates the same certificate between the SELECT and UPDATE, the cleanup will clear the newly-set previous certificate, bypassing its grace period.

**Attack Scenario:** This is not directly exploitable by an external attacker. It requires a coincidence: the rotation job must be running cleanup at the exact moment an admin triggers a manual certificate rotation for the same SP. The result is that the previous certificate (which SPs may still be using during the grace window) is prematurely cleared, causing brief SSO validation failures for that SP.

**Evidence:**
```python
# rotate_certificates.py:287 - No re-check of grace period timestamp
result = database.sp_signing_certificates.clear_previous_signing_certificate(
    tenant_id, sp_id
)

# sp_signing_certificates.py:166-180 - UPDATE has no WHERE guard on timestamp
update sp_signing_certificates
set previous_certificate_pem = null,
    previous_private_key_pem_enc = null,
    previous_expires_at = null,
    rotation_grace_period_ends_at = null
where sp_id = :sp_id  -- No: AND rotation_grace_period_ends_at < now()
returning ...
```
**Impact:** Premature grace period termination causing brief SSO disruption for a single SP. No data leakage or privilege escalation.
**Remediation:** Add a timestamp guard to the cleanup UPDATE:

```sql
update sp_signing_certificates
set previous_certificate_pem = null,
    previous_private_key_pem_enc = null,
    previous_expires_at = null,
    rotation_grace_period_ends_at = null
where sp_id = :sp_id
  and rotation_grace_period_ends_at is not null
  and rotation_grace_period_ends_at < now()
returning ...
```

---
