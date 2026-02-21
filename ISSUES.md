# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 2 | Security (A05, A03) |
| Medium | 2 | Security (A02) |
| Low | 2 | Security (A01, A05) |

**Last security scan:** 2026-02-21 (full OWASP assessment, first review)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## [SECURITY] Session cookie missing `Secure` flag in production

**Found in:** `app/main.py:60`
**Severity:** High
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** Starlette's `SessionMiddleware` defaults to `https_only=False`. The session cookie can be transmitted over plain HTTP, enabling session hijacking via network sniffing. HSTS mitigates this after the first visit, but the initial request is vulnerable.
**Remediation:** Pass `https_only=not settings.IS_DEV` to `DynamicSessionMiddleware`.

---

## [SECURITY] Inconsistent defusedxml usage allows XML bomb attacks

**Found in:** `app/utils/saml.py:539`, `app/services/branding.py:153`
**Severity:** High
**OWASP Category:** A03:2021 - Injection
**Description:** Two locations parse untrusted XML using stdlib `xml.etree.ElementTree` instead of `defusedxml`, which is used correctly elsewhere in the project (`saml_idp.py`, `saml_authn_request.py`, `saml_slo.py`). The stdlib parser is vulnerable to billion-laughs (entity expansion) DoS attacks. In `saml.py`, the function parses untrusted SAML responses before any signature validation. In `branding.py`, manual `<!ENTITY`/`<!DOCTYPE` string checks provide partial protection but can be bypassed with case variations or whitespace.
**Remediation:** Replace `ET.fromstring()` with `DefusedET.fromstring()` in both files.

---

## [SECURITY] TLS verification disabled for internal metadata fetching

**Found in:** `app/utils/saml.py:297-299`, `app/utils/saml_idp.py:299-301`
**Severity:** Medium
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** When fetching SAML metadata from URLs matching `*.BASE_DOMAIN`, TLS certificate verification is completely disabled (`ssl.CERT_NONE`, `check_hostname=False`) to route through the Docker reverse-proxy. An attacker on the internal network could MITM this connection and inject malicious metadata containing forged signing certificates.
**Remediation:** Add the reverse-proxy's CA certificate to a custom trust store instead of disabling verification entirely.

---

## [SECURITY] Weak key derivation fallback for SAML private key encryption

**Found in:** `app/utils/saml.py:27-30`
**Severity:** Medium
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** When `SAML_KEY_ENCRYPTION_KEY` is not valid base64, the fallback derives a Fernet key using raw SHA256 (no salt, no iteration count). This is not a proper key derivation function. Only triggered when the env var is not a valid 32-byte base64 value.
**Remediation:** Use HKDF from `cryptography.hazmat.primitives.kdf.hkdf` for the fallback path.

---

## [SECURITY] SSO consent flow not bound to authenticated user

**Found in:** `app/routers/saml_idp/sso.py:127-138`
**Severity:** Low
**OWASP Category:** A01:2021 - Broken Access Control
**Description:** The pending SSO context (`pending_sso_sp_id`, etc.) is stored in the session without recording which `user_id` initiated it. If a session were reused by a different user, they could complete another user's SSO flow. Session regeneration on login prevents this in practice.
**Remediation:** Store `pending_sso_user_id` in session and validate it matches on consent.

---

## [SECURITY] Trust cookie uses SameSite=Lax instead of Strict

**Found in:** `app/routers/auth/login.py:245-246`
**Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** The email verification trust cookie uses `samesite="lax"`, allowing it to be sent on top-level cross-site navigations. The cookie is encrypted and only bypasses email verification (not authentication), so impact is minimal.
**Remediation:** Change to `samesite="strict"`.

---
