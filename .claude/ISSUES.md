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
| Low | 2 | Copy |
| **High** | **1** | **Security (passkey_auth review)** |
| Low | 1 | Security |
| Medium | 3 | Security (passkey_auth review) |
| Low | 1 | Security (passkey_auth review) |
| Low | 1 | Docs (passkey_auth review) |
| Low | 6 | Copy (passkey_auth review) |

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

## [SECURITY] Enhanced policy bypass: passkey user can authenticate via email OTP

**Found in:** `app/services/users/auth_policy.py::user_must_enroll_enhanced`, `app/routers/mfa.py::mfa_verify`
**Severity:** High
**Description:** Under `required_auth_strength = 'enhanced'`, a user with `mfa_method = 'email'` and at least one registered passkey can sign in via password + email OTP by abandoning the passkey ceremony. The enforcement check `user_must_enroll_enhanced` returns `False` because the user has a passkey (line 46-47 counts credentials). This conflates "has a strong method available" with "used a strong method for this login." The design decision states: "Email OTP is a valid step-up method iff tenant policy is `baseline`." Under `enhanced`, email OTP should never be the final authentication factor, regardless of what other methods the user has registered.
**Evidence:**
- `app/services/users/auth_policy.py:46-47` short-circuits on `count_credentials > 0`.
- `app/routers/mfa.py:134` calls `user_must_enroll_enhanced` after email OTP succeeds; the passkey count makes it return False and the login completes.
- E2E test `tests/e2e/test_enhanced_auth_policy.py::test_passkey_user_cannot_bypass_via_email_otp` demonstrates the bug (marked `xfail`).
**Impact:** An attacker who phishes a password and intercepts an email OTP can authenticate as a passkey-protected user under enhanced policy. The entire point of enhanced policy is to block email OTP. This undermines the security guarantee admins expect when enabling the setting.
**Suggested fix:** In `mfa_verify`, after successful email OTP verification, if the tenant policy is `enhanced`, always redirect to the enrollment page (or a "use your passkey" interstitial), regardless of whether the user has passkeys registered. The enrollment page already handles passkey users gracefully. Alternatively, add a new check in `user_must_enroll_enhanced` that accepts the MFA method used for the current login and rejects email OTP under enhanced policy even when passkeys exist.
**Related cleanup:** The `mfa_method` CHECK constraint includes a `passcode` value that no code path ever sets. Remove it from the schema constraint and any service/template logic that references it. Simplifying the set of valid MFA methods makes the policy enforcement logic easier to reason about.

---

## [SECURITY] Passkey clone detection relies on py_webauthn error-string substring match

**Found in:** `app/services/webauthn.py::complete_authentication` (sign-count regression branch)
**Severity:** Low
**Description:** Clone detection rejects a WebAuthn assertion when `py_webauthn` raises `InvalidAuthenticationResponse` and the error message contains the substring `"sign count"` or `"counter"`. `py_webauthn` does not expose a typed exception for this case, so the service branches on the library's human-readable wording. A future library version that rephrases the error would fall through to the `bad_signature` branch: the assertion is still rejected, but the credential is NOT deleted and the event reason is `bad_signature` instead of `clone_suspected`. That's a weaker security posture (attacker keeps the cloned credential) and noisier audit.
**Evidence:** `app/services/webauthn.py` (search for `"sign count"` substring). The py_webauthn 2.7.1 message today is `"Response sign count of X was not greater than..."`.
**Impact:** Correctness bound (never let a sign-count regression slip past on `backup_eligible=false`) is preserved, but the cloned credential is not automatically deleted and the `passkey_auth_failure` event reason becomes misleading. Silent degradation on library bump.
**Suggested fix:** Either catch a typed exception if a newer py_webauthn release adds one, or move the sign-count decision into `app/utils/webauthn.py::verify_authentication` so the service receives a typed result (`WebAuthnAuthResult(ok=False, reason="clone_suspected")`) rather than parsing a message string. Add a pin test so any library upgrade that reshapes the error wording forces the issue to the surface.

---

## [SECURITY] TOCTOU: passkey `complete_authentication` skips user eligibility recheck

**Found in:** `app/services/webauthn.py::complete_authentication`
**Severity:** Medium
**Description:** `begin_authentication` runs `_resolve_eligible_user` (rejects nonexistent, IdP-linked, inactivated, zero-passkey). `complete_authentication` only fetches the credential row and verifies the signature. Within the 5 minute challenge TTL an admin can inactivate the user, reassign them to a SAML IdP, or delete their last passkey, and the pending ceremony still completes a sign-in.
**Evidence:** `app/services/webauthn.py` around line 552+. `_resolve_eligible_user` is not called from the complete path.
**Impact:** Inactivated user signs in successfully; IdP-linked user bypasses IdP redirect; audit log shows `passkey_auth_success` + `user_signed_in` for an account that should already be locked. Window is bounded by the 5 minute challenge TTL but the race is real under admin-triggered lockout.
**Suggested fix:** In `complete_authentication`, after resolving the credential row and before session finalisation, re-read the user (`database.users.get_user_by_id(tenant_id, pending_user_id)`) and reject if `is_inactivated=True`, `saml_idp_id is not None`, or user not found. Emit `passkey_auth_failure(reason="eligibility_revoked")` on rejection.

---

## [SECURITY] Passkey registration + enhanced-enrollment TOTP verify have no rate limit

**Found in:** `app/routers/auth/enhanced_enrollment.py`, `app/routers/account_passkeys.py`, `app/routers/api/v1/account_passkeys.py`
**Severity:** Medium
**Description:** Registration begin/complete (both HTML and API) and `POST /login/enroll-enhanced-auth` (TOTP verify) have no per-user or per-IP rate limits. Passkey login `complete` has `passkey_complete:ip:{ip}` 30/5min; registration does not. Enhanced-enrollment TOTP verify can be spammed within a single code window.
**Evidence:**
- `app/routers/auth/enhanced_enrollment.py` lines 171-272 (TOTP verify, passkey begin/complete) — no `ratelimit.prevent` calls.
- `app/routers/account_passkeys.py` lines 40-91 — no rate limits.
- `app/routers/api/v1/account_passkeys.py` lines 48-96 — no rate limits.
**Impact:** (1) Hijacked pre-auth enrollment session can brute-force 6-digit TOTP code within the 30-second validity window. Feasible over a few minutes at 100+ req/s. (2) Authenticated session (or compromised cookie) can spam registration begin/complete, consuming expensive crypto on the server.
**Suggested fix:**
- `ratelimit.prevent("enroll_totp_verify:user:{user_id}", limit=5, timespan=MINUTE*5, user_id=pending_user_id)` on TOTP verify.
- `ratelimit.prevent("passkey_enroll_complete:user:{user_id}", limit=10, timespan=MINUTE*5, user_id=...)` on both HTML and API complete-registration endpoints.
- Similar begin-side soft cap.

---

## [SECURITY] `show_passkey_first` render branch is a passkey-existence oracle

**Found in:** `app/routers/auth/login.py` lines 82-90
**Severity:** Medium
**Description:** `GET /login?prefill_email=<email>&show_password=true` calls `webauthn_service.user_has_passkey_for_email(tenant_id, email)`. If the user exists and has ≥ 1 passkey, the page auto-starts the ceremony; otherwise only the password form renders. Observable at GET time with no rate limit. Attacker can enumerate "user exists AND has passkey" without a POST.
**Evidence:** `app/routers/auth/login.py:82-90` branches the template on the boolean.
**Impact:** Targeted attacks can prefer/avoid passkey users (e.g., pick users with passkeys to attempt authenticator theft, or avoid them to stick with phishable MFA paths). Partial user-existence oracle.
**Suggested fix:** (a) Add rate limiting to `GET /login` when both `show_password=true` and `prefill_email` are set; or (b) always render the passkey-first variant when `show_password=true`, letting the begin endpoint 404 silently and fall back to password.

---

## [SECURITY] Plain admin can revoke super_admin's passkey

**Found in:** `app/services/webauthn.py::admin_revoke_credential`
**Severity:** Low
**Description:** `admin_revoke_credential` requires `require_admin` (admin or super_admin). A plain admin can revoke a super_admin's passkey. Combined with `/users/{user_id}/force-password-reset` (same permission level), an admin can materially degrade a super_admin's auth posture. Not direct privilege escalation but inconsistent with the usual "lower role cannot act on higher role" convention.
**Evidence:** `app/services/webauthn.py` lines 369-442; `app/routers/users/detail.py` lines 436-460.
**Impact:** Plain admin can kick a super_admin out of active OAuth2 sessions (via the OAuth2 token revocation coupled to passkey revoke) and force them through enhanced-enrollment again.
**Suggested fix:** In `admin_revoke_credential`, if target user role is `super_admin` and requesting user is not `super_admin`, raise `ForbiddenError`. Apply the same guard to `force_password_reset` for consistency if not already present.

---

## [DOCS] authentication-policy.md: MFA reset incorrectly claims passkeys are cleared

**Found in:** `docs/admin-guide/security/authentication-policy.md` Recovery section (lines 31-39)
**Severity:** Low
**Description:** Doc says "The user's TOTP secret and passkeys are cleared" on MFA reset. `reset_mfa` in `app/services/mfa.py:540-584` only clears TOTP secret + backup codes; passkeys are untouched (admins revoke passkeys individually via the user detail Profile tab).
**Impact:** Admin expectations diverge from behaviour. A super_admin reading this may believe MFA reset fully resets auth; passkey-using target still signs in via passkey.
**Suggested fix:** Replace with: "This clears the user's TOTP secret and backup codes. It does not delete any registered passkeys; those must be revoked individually from the user's Profile tab (see 'Revoking a single passkey' below). On the next sign-in the user goes through the enrollment flow again unless they still have a passkey that satisfies the enhanced policy." Also update `docs/admin-guide/security/two-step-verification.md` reset section to match. Add passkeys entry to `docs/user-guide/index.md` and `docs/admin-guide/security/index.md` nav. Add "Signing in with a passkey" subsection to `docs/user-guide/signing-in.md`. Update `docs/user-guide/two-step-verification.md` backup-codes section to mention passkey recovery.

---

## [COPY] settings_security_tab_authentication.html: stale "future release" passkey reference

**Found in:** `app/templates/settings_security_tab_authentication.html` lines 17-21 and 73-75
**Severity:** Low
**Description:** Two strings still say passkey support is "in a future release":
- Line 17-21: "forced to set up an authenticator app (or, in a future release, a passkey)".
- Line 73-75: "redirected to set up an authenticator app the next time they sign in" (omits passkey option).

Passkey enrollment is live per iteration 4 (`enroll_enhanced_auth.html` renders both TOTP and passkey cards).
**Suggested fix:**
- Line 17-21: "forced to set up an authenticator app or passkey the next time they sign in."
- Line 73-75: "redirected to set up an authenticator app or a passkey the next time they sign in."

---

## [COPY] settings_mfa.html: backup-code description omits passkeys

**Found in:** `app/templates/settings_mfa.html` line 49
**Severity:** Low
**Description:** Current: "Backup codes can be used once each to sign in if you lose access to your authenticator app." Backup codes are the recovery fallback for passkey users too (first passkey registration issues them).
**Suggested fix:** "Backup codes can be used once each to sign in if you lose access to your authenticator app or all your passkeys."

---

## [COPY] user_detail_base.html: mfa_reset banner misleads when target has a passkey

**Found in:** `app/templates/user_detail_base.html` line 36
**Severity:** Low
**Description:** Current: "User's two-step verification has been reset. They will use email codes on next sign-in." Wrong if the target has a passkey, since `reset_mfa` does not delete passkeys.
**Suggested fix:** "User's two-step verification has been reset. Any TOTP secret and backup codes are cleared. Registered passkeys are not affected."

---

## [COPY] user_detail_base.html: self-revoke error banner gives no navigation path

**Found in:** `app/templates/user_detail_base.html` lines 117-118
**Severity:** Low
**Description:** Current: "You cannot revoke your own passkey from the admin view. Use the account passkeys page instead."
**Suggested fix:** "You cannot revoke your own passkey from the admin view. Go to Account > Two-Step Verification to manage your own passkeys."

---

## [COPY] user_detail_tab_profile.html: Verification Method row ignores passkeys

**Found in:** `app/templates/user_detail_tab_profile.html` lines 33-45
**Severity:** Low
**Description:** "Two-Step Verification: Yes/No" and "Verification Method: TOTP/EMAIL/Not set" are driven by `mfa_enabled` and `mfa_method`. A passkey-only user shows "Verification Method: Not set" while the Passkeys section immediately below lists registered passkeys.
**Impact:** Structural misrepresentation of user's real auth posture; not a pure copy fix.
**Suggested fix:** Add a "Passkeys: N registered" row or rename/rescope the Verification Method section. Coordinate with `/tech-writer` on terminology.

---

## [COPY] login.html: "Use password instead" should be a button, not an anchor

**Found in:** `app/templates/login.html` lines 76-79
**Severity:** Low
**Description:** `<a href="#">` with `preventDefault` for an action that does not navigate. Accessibility polish.
**Suggested fix:** Replace with `<button type="button">`.

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

