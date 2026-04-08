# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | SAML Security |
| Medium | 2 | File Structure, SAML Security |
| Low | 1 | Duplication |

**Last security scan:** 2026-04-08 (targeted: SAML SP decryption error handling, padding oracle surface)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-04-02 (filter panel, audit pages, export page, email templates, terminology)

---

## [SECURITY] CBC Padding Oracle: ACS error responses leak decryption failure details

**Found in:** `app/templates/saml_error.html:56`, `app/routers/saml/authentication.py:258-262, 441-452`, `app/routers/saml/authentication.py:216-296`
**Severity:** High
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** The SAML ACS error page renders the raw python3-saml/xmlsec error string (`error_detail`) directly to the browser, and the `error_type` classification distinguishes decryption failures ("Invalid SSO Response") from signature failures ("Signature Verification Failed"). Together these create an observable message-channel oracle for CBC padding attacks (Jager/Somorovsky 2011) against AES-CBC encrypted assertions.

WeftID's SP metadata unconditionally advertises an encryption certificate (`idp_sp_certificates.py:224`), so upstream IdPs will encrypt assertions. The signed assertion is inside the encrypted envelope, meaning decryption must happen before signature validation and the two failure modes are distinguishable. There is no rate limiting on the ACS endpoints, so an attacker can make thousands of oracle queries against a captured assertion.

**Attack Scenario:** Attacker intercepts a valid encrypted SAML response for a target user (e.g., from a compromised network path or by replaying from browser history). Attacker submits bit-flipped variants to `/saml/acs/{idp_id}`. Padding failures return "Invalid SSO Response" with an xmlsec error string; valid-padding-but-bad-signature returns "Signature Verification Failed". After ~3000 queries the attacker can recover the plaintext assertion, obtaining the user's identity attributes.

**Evidence:**

`saml_error.html:53-58` — raw error string shown to user:
```html
{% if error_detail %}
<p class="... font-mono break-all">{{ error_detail }}</p>
{% endif %}
```

`authentication.py:258-262` — error_type leaks failure mode:
```python
error_type = "signature_error" if "signature" in str(e).lower() else "invalid_response"
```

`idp_sp_certificates.py:224` — signing cert advertised as encryption cert:
```python
encryption_certificate_pem=cert["certificate_pem"],
```

**Remediation:**

1. **Remove `error_detail` from `saml_error.html`** — the detail is already stored server-side via `store_saml_debug_entry()`. End users need only a generic message. Remove or gate the entire `{% if error_detail %}` block.

2. **Flatten error_type for decryption/validation failures** — any failure during or after decryption should map to a single generic type (e.g., `"auth_failed"`), not distinguish `signature_error` from `invalid_response`. The real classification is still captured in the debug entry.

3. **Add rate limiting to ACS endpoints** — add `ratelimit.prevent()` calls in `saml_acs()` and `saml_acs_per_idp()` keyed on IP, capped at ~20 requests per 5 minutes per IP. Without this, oracle queries are unconstrained.

---

## [SECURITY] CBC Padding Oracle: No rate limiting on SAML ACS endpoints

**Found in:** `app/routers/saml/authentication.py:216-296, 349-553`
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** Neither `/saml/acs` nor `/saml/acs/{idp_id}` applies rate limiting. This makes the padding oracle attack described above practical: an attacker can submit thousands of oracle queries with no friction. It also leaves the endpoints open to credential-stuffing-style assertion replay attempts.
**Remediation:** Add `ratelimit.prevent("saml_acs:ip:{ip}", limit=20, timespan=MINUTE * 5, ip=client_ip)` at the top of both ACS handlers, using `_get_client_ip(request)` (already available via `routers.auth._helpers`). Return a generic 429 redirect on limit exceeded.

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

