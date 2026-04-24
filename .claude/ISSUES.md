# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 1 | Security (Auth Strength) |
| Medium | 1 | Security (Unbounded Input) |
| Low | 1 | Security (Host Header Trust) |
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Duplication (pre-existing) |
| Low | 1 | Copy |

**Last security scan:** 2026-04-24 (targeted: all code from last 14 days, all OWASP categories; 3 findings)
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

## [SECURITY] Passkey verification accepts assertions without User Verification (UV)

**Found in:** `app/utils/webauthn.py:146` (default `require_user_verification=False`), `app/utils/webauthn.py:107, 132` (UV set to `PREFERRED`), callers in `app/services/webauthn.py` do not override the default.
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** Registration and authentication ceremonies set `UserVerificationRequirement.PREFERRED` and verify with `require_user_verification=False`. Under the tenant `enhanced` auth strength policy (`app/services/users/auth_policy.py:31-66`) a registered passkey is treated as satisfying strong, single-step authentication (a passkey holder bypasses email-OTP enrollment). With UV only preferred, an authenticator can return an assertion with the UV flag clear, meaning the sign-in proves only device presence, not a PIN/biometric check. That reduces a passkey to "something you have" and breaks the policy's implicit assumption of phishing-resistant, multi-factor strength (NIST AAL2+). An unlocked device left on a desk is enough to sign in.
**Attack Scenario:** Attacker borrows an unlocked laptop/phone with a platform authenticator (Windows Hello idle, Touch ID unlocked session, etc.) and authenticates to WeftID. The service accepts the UV-absent assertion and completes login because UV is preferred-not-required. The tenant admin had selected `enhanced` believing passkeys were phishing-resistant multi-factor; policy expectation is violated.
**Evidence:**
```python
# app/utils/webauthn.py:106-109
authenticator_selection=AuthenticatorSelectionCriteria(
    user_verification=UserVerificationRequirement.PREFERRED,
    resident_key=ResidentKeyRequirement.PREFERRED,
),
# app/utils/webauthn.py:146 (default)
require_user_verification: bool = False,
```
**Impact:** Enhanced-policy tenants get a weaker authentication guarantee than the UI implies. Bypasses the "phishing-resistant factor on its own" comment in `auth_policy.py:31`.
**Remediation:** Set `user_verification=UserVerificationRequirement.REQUIRED` in both `generate_registration_options_for_user` and `generate_authentication_options_for_user`, and pass `require_user_verification=True` when verifying authentication assertions for passkey login. If keeping a mixed policy is intentional, gate the `enhanced`-satisfying credit on the stored `uv=True` flag (persist `verified.user_verified` on registration; only count passkeys with UV toward enhanced strength).

---

## [SECURITY] Unbounded JSON body on passkey ceremony endpoints

**Found in:** `app/schemas/webauthn.py:38, 111` (`response: dict` with no size bound); `app/routers/auth/passkey_login.py:64-98`, `app/routers/account_passkeys.py:71-116`, `app/routers/api/v1/account_passkeys.py:82`, `app/routers/auth/enhanced_enrollment.py:222-265`. Also: no global ASGI request-size middleware; `deploy/Caddyfile` sets no `request_body max_size`.
**Severity:** Medium
**OWASP Category:** Unbounded Input / A04:2021 - Insecure Design (resource exhaustion)
**Description:** The WebAuthn ceremony schemas accept `response: dict` with no depth/size bound, and FastAPI's default body parser reads the whole JSON into memory before schema validation. Caddy does not cap body size. The pre-auth endpoint `POST /login/passkey/complete` is rate-limited to 30 requests/5 min/IP (`passkey_login.py:81-92`), which does not meaningfully cap memory: an attacker can post 100 MB+ JSON per request, legitimately 600 MB/min/IP of parser allocation. From a few IPs this comfortably exhausts the worker process.
**Attack Scenario:** Pre-auth attacker POSTs very large JSON bodies (or pathological nesting) to `/login/passkey/complete` from multiple IPs. The app reads and parses each body before rejecting via Pydantic, driving the worker process into OOM / CPU saturation. Same surface on `/account/passkeys/complete-registration` (requires any authenticated user) and on `/login/enroll-enhanced-auth/passkey/complete` (requires partial-auth session).
**Evidence:**
```python
# app/schemas/webauthn.py:111
class CompleteAuthenticationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    response: dict = Field(
        ...,
        description="PublicKeyCredential JSON produced by navigator.credentials.get()",
    )
```
No `max_length` / size ceiling anywhere on the payload; no request-size middleware in `app/main.py`.
**Impact:** DoS of the passkey login path (and by extension all auth) with modest attacker resources. Also affects any other JSON endpoint, but passkey complete is the attractive target because it's pre-auth.
**Remediation:** Two complementary fixes:
1. Add a request body size middleware (or enforce in reverse proxy) with a conservative cap, e.g. 128 KiB for JSON auth endpoints, 1 MiB globally. In Caddy: add `request_body { max_size 1MB }` to the reverse_proxy block. In ASGI: install a lightweight middleware that checks `Content-Length` and reads at most N bytes from the body.
2. Tighten the schema: replace `response: dict` with an explicit `PublicKeyCredentialResponse` model (id, rawId with `max_length`, type, response.{clientDataJSON, attestationObject/authenticatorData, signature, userHandle} all with `max_length`). That gives per-field bounds even if the proxy cap is missing.

---

## [SECURITY] rp_id / origin derivation trusts X-Forwarded-Host without a trust boundary

**Found in:** `app/utils/webauthn.py:49-80`, using `app/dependencies.py:24-32` (`normalize_host`)
**Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration (defense-in-depth)
**Description:** `rp_id_for_request` and `origin_for_request` unconditionally read `X-Forwarded-Host` and `X-Forwarded-Proto` to compute the WebAuthn Relying Party ID and expected origin for ceremony verification. The app has no notion of trusted proxies and no allowlist on the RP ID. Production deployment puts Caddy in front of the app and Docker does not publish app port 8000, so today these headers are proxy-controlled. If the app is ever exposed directly (misconfigured compose override, debug port publish, test harness, internal network reach), an attacker sending `X-Forwarded-Host: attacker.example.com` can register a passkey scoped to any RP ID they like and then phish a victim on that attacker domain.
**Attack Scenario:** Attacker reaches app container directly on an internal network or via a misconfigured host port. They start a passkey registration while spoofing `X-Forwarded-Host: their-own-subdomain.tenant.weftid.com`. The browser on the attacker's phishing page performs the ceremony successfully because the app reports the spoofed host as expected origin. The resulting credential can later be used against the legitimate tenant without the victim ever visiting the real site.
**Evidence:**
```python
# app/utils/webauthn.py:56
host = normalize_host(request.headers.get("x-forwarded-host") or request.headers.get("host"))
return host
# app/utils/webauthn.py:76-80
scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
host_header = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
```
**Impact:** Defense-in-depth failure. Not directly exploitable in the current production topology, but the security of passkey RP binding depends entirely on the reverse proxy being the only ingress — a deployment-level assumption that is not enforced in code.
**Remediation:** Either (a) compute RP ID server-side from the tenant record (`tenant.subdomain + "." + settings.BASE_DOMAIN`) rather than from request headers, and reject ceremonies if the browser-reported origin does not match; or (b) add a `TRUSTED_PROXIES` setting and only honor `X-Forwarded-*` when the immediate peer matches it (Starlette `ProxyHeadersMiddleware` with a trusted-hosts allowlist). Option (a) is simpler here because tenants are already 1:1 with subdomain.

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

