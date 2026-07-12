# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 3 | Security ×2 (OAuth2 bearer-validation DoS, OIDC access-revocation lag), File Structure (pre-existing) |
| Low | 2 | Security (authorize flow skips is_active), Upload-auth temp-file leak (warning-ignored, tracked) |
| Deps | 1 | pygments (LOW, blocked by upstream) |

Note: the three OIDC final-review enhancements (signing-key rotation surface,
"Deactivated" badge copy, OIDC provider browser e2e) and the HIGH
silently-broken-UNSCOPED-worker-sweeps bug were resolved on the oidc-provider
branch (2026-07-09); see ISSUES_ARCHIVE.md.

Note: the six inbound-SCIM final-review items (cross-IdP rebind audit event, actor
consistency, private-helper import boundary, `list_active_tokens` dead code, canonical-email
validation, Pydantic `max_length`) plus the project-wide proxy-headers / forwarded-host trust
boundary were resolved on the inbound-scim branch (2026-05-29); see ISSUES_ARCHIVE.md.

**Last security scan:** 2026-07-09 (full sweep of the oidc-provider branch vs main, all OWASP categories: OIDC signing keys/JWKS/discovery, ID-token issuance, userinfo, client access control, migrations 0051-0055, templates, worker sweeps. Overall well-defended: parameterized SQL, strict RLS + hardened SECURITY DEFINER accessors, encrypted key material, PKCE/one-time codes intact, CSRF on all new forms, bounded inputs with matching DB CHECKs, regression hunt against ISSUES_ARCHIVE patterns clean. Found 2 MEDIUM + 1 LOW, logged below)
**Previous security scan:** 2026-06-21 (targeted 60-day sweep of forward-auth proxy, inbound/outbound SCIM, WebAuthn, and user-attributes→SAML flow; forward-auth, inbound SCIM, and WebAuthn verified well-defended; the 1 HIGH SSRF + 2 MEDIUM attribute-provenance + Low DiD bundle it found have since been resolved, see ISSUES_ARCHIVE.md)
**Last compliance scan:** 2026-06-21 (automated checker clean, 0 violations across 1612 files; targeted 60-day manual sweep of SCIM, WebAuthn, attributes/auth-policy/settings, forward-auth proxy, and migrations 0031-0048; the 6 warning-level judgment findings have since been resolved, see ISSUES_ARCHIVE.md)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-06-20 (cryptography 48.0.0→48.0.1, python-multipart 0.0.29→0.0.31, pip 26.1.1→26.1.2, msgpack 1.1.2→1.2.1, starlette 1.0.1→1.3.1 bumped, clearing all 6 HIGH/MED CVEs; full suite green; pygments still pinned `<2.20`, see [DEPS] entry below)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-24 (terminology sweep: "two-step verification" → "sign-in strength" / "sign-in methods" where passkeys make "two-step" inaccurate)

---

## [SECURITY] Auth Failures: bearer validation Argon2-verifies every live token in the tenant

**Found in:** `app/database/oauth2/tokens.py:145-167` (`validate_token`), `app/database/oauth2/tokens.py:180-207` (`validate_refresh_token`), `app/database/oauth2/authorization.py:105-123` (`validate_and_consume_code`)
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures (resource exhaustion)
**Status:** Pre-existing on `main`; newly reachable through the OIDC `/userinfo` endpoint added on this branch.

**Description:** Tokens are stored as Argon2 hashes with no lookup key, so validation cannot index. `validate_token()` selects **every non-expired access token in the tenant** and calls `oauth2.verify_token_hash()` (Argon2 `verify`) in a Python loop until one matches. A token that matches nothing runs Argon2 once per live token in the tenant.

**Evidence:**
```python
# app/database/oauth2/tokens.py:145
tokens = fetchall(
    tenant_id,
    """
    select id, token_hash, user_id, tenant_id, client_id, expires_at, scope
    from oauth2_tokens
    where token_type = 'access'
      and expires_at > now()
    """,
    {},
)
for token_record in tokens:
    if oauth2.verify_token_hash(token, token_record["token_hash"]):  # Argon2 per row
```

**Attack Scenario:** An attacker who can reach a tenant host (`/userinfo` needs no valid credential to trigger the work — the bearer dependency calls `validate_token` before any authorization check) sends requests with a garbage `Authorization: Bearer <64 random chars>` header. Each request forces `N` Argon2 verifications, where `N` is the tenant's count of live access tokens. Argon2 with default `PasswordHasher()` parameters costs roughly tens of milliseconds and ~64 MiB of memory per verification. In a tenant with a few hundred active tokens, one request occupies a worker for seconds and allocates gigabytes cumulatively. A handful of concurrent requests exhausts the worker pool and the memory ceiling. The same amplification exists on `/oauth2/token` (`validate_refresh_token`, `validate_and_consume_code`), which is CSRF-exempt and unauthenticated up to the client-secret check.

Note the amplification grows with tenant success: the more legitimate tokens a tenant has, the cheaper the attack is per unit of damage.

**Exploitability:** Easy (no credential needed, single-header request).
**Impact:** Denial of service against a tenant's entire auth surface (API, token endpoint, userinfo). No data disclosure.

**Remediation:** Give the token table an indexed, non-secret lookup key so validation resolves exactly one row and performs exactly one Argon2 verification. The standard shape is a fast unkeyed digest for lookup plus the existing slow hash for verification:

```python
# Migration: add a lookup column + index.
#   ALTER TABLE oauth2_tokens ADD COLUMN token_lookup char(64);
#   CREATE UNIQUE INDEX idx_oauth2_tokens_lookup ON oauth2_tokens (tenant_id, token_lookup);

# app/oauth2.py
def token_lookup(token: str) -> str:
    """Indexed lookup digest. Not a credential store: the token is already
    256 bits of `secrets` entropy, so a fast digest is not brute-forceable."""
    return hashlib.sha256(token.encode()).hexdigest()

# app/database/oauth2/tokens.py
row = fetchone(
    tenant_id,
    """
    select id, token_hash, user_id, tenant_id, client_id, expires_at, scope
    from oauth2_tokens
    where token_type = 'access' and token_lookup = :lookup and expires_at > now()
    """,
    {"lookup": oauth2.token_lookup(token)},
)
if row and oauth2.verify_token_hash(token, row["token_hash"]):
    return {...}
return None
```

Because `generate_opaque_token()` already draws 256 bits from `secrets.token_bytes(32)`, the SHA-256 lookup column is not a guessable-password problem: there is no dictionary to attack. Argon2 is retained on the single candidate row so a database dump still cannot be replayed if the reasoning about entropy ever changes. Apply the same pattern to `oauth2_authorization_codes`.

A short-term mitigation (rate-limit `/userinfo` and `/oauth2/token` per source IP) reduces but does not remove the amplification, since a single request still costs `N` verifications.

**Files Affected:** `app/database/oauth2/tokens.py`, `app/database/oauth2/authorization.py`, `app/oauth2.py`, new migration

---

## [SECURITY] Broken Access Control: revoking OIDC app access leaves tokens live for up to 30 days

**Found in:** `app/routers/oauth2.py:487-529` (`refresh_token` grant), `app/services/oidc/clients.py:243-274` (`remove_client_group_assignment`), `app/services/oidc/clients.py:57-116` (`set_oidc_settings`)
**Severity:** Medium
**OWASP Category:** A01:2021 - Broken Access Control

**Description:** Group-based access control for OIDC clients is enforced at exactly two points, both inside the authorize flow: `authorize_page` (GET, before the consent page) and `authorize_grant` (POST, before the code is issued). Nothing re-checks the grant afterwards. Revoking access does not revoke the credentials that access already produced:

- `remove_client_group_assignment()` deletes the grant row and logs, but never calls `revoke_all_user_tokens` / `revoke_all_client_tokens`.
- `set_oidc_settings(available_to_all=False)` narrows the policy with no token revocation.
- The `refresh_token` grant re-checks only that the client exists, authenticates, and is active. It never consults `user_can_access_oauth2_client()`, so it happily mints fresh access tokens for a user who no longer holds any grant.

Contrast with the paths that *do* get this right: `deactivate_client()` calls `revoke_all_client_tokens()`, and user inactivation (`app/services/users/state.py:97`) calls `revoke_all_user_tokens()`. The new OIDC revocation surface is the one that omits it.

**Attack Scenario:** An employee signs in to an OIDC-enabled app and receives an access token (1 h) plus a refresh token (30 days, `OAUTH2_REFRESH_TOKEN_EXPIRY`). The employee is then removed from the group that grants access to that app (or the app is switched from `available_to_all` to group-based, and they are in no assigned group). An admin reasonably believes access is revoked: the audit log shows the unassignment, and a fresh authorize attempt is denied with `oidc_access_denied`.

In reality the ex-member keeps calling `POST /oauth2/token` with `grant_type=refresh_token` and receives a new 1-hour access token every time, for the full 30-day refresh window. That token is accepted at `/userinfo`, which re-checks only `oidc_enabled` on the client, never the user's group grant. Profile, email, and `groups` claims keep flowing. The `groups` claim will even reflect the user's *current* (now empty) memberships, so a downstream RP doing its own group-based authorization may see the removal while WeftID keeps authenticating them.

The same window applies to offboarding-adjacent revocations that are *not* full user deactivation, which is the common case for "remove this contractor from the billing app."

**Exploitability:** Easy (the ex-member already holds the refresh token; no attack technique required, just continued use).
**Impact:** Revoked users retain authenticated access to a downstream application and continue receiving identity claims for up to 30 days. Privilege revocation is not effective.

**Remediation:** Two changes, both needed.

1. Re-check the grant in the `refresh_token` grant, so a revoked user cannot mint new access tokens:

```python
# app/routers/oauth2.py, refresh_token branch, after validate_refresh_token()
if client.get("oidc_enabled") and not oidc_service.user_can_access_client(
    tenant_id=tenant_id,
    user_id=str(token_data["user_id"]),
    client_uuid=str(client["id"]),
    client_id=client["client_id"],
    client_name=client.get("name"),
):
    raise HTTPException(
        status_code=400,
        detail={"error": "invalid_grant", "error_description": "Access has been revoked"},
    )
```

2. Revoke outstanding tokens when a grant is withdrawn, mirroring `deactivate_client()`. In `remove_client_group_assignment()` and in `set_oidc_settings()` when `available_to_all` flips to `False`, revoke the tokens of users who lost access. The precise set is "users holding a token for this client who no longer satisfy `user_can_access_oauth2_client`"; a simple correct implementation revokes this client's tokens for the affected users, or (blunter, still acceptable) all of the client's tokens via `database.oauth2.revoke_all_client_tokens(tenant_id, str(client["id"]))`, forcing everyone to re-authorize.

Fix (1) alone bounds exposure to the access-token lifetime (1 h). Fix (2) closes it immediately. Note that `/userinfo` still accepts an unexpired access token in the gap, which is why (2) matters.

**Files Affected:** `app/routers/oauth2.py`, `app/services/oidc/clients.py`, tests

---

## [SECURITY] Broken Access Control: authorize flow issues codes for deactivated clients

**Found in:** `app/routers/oauth2.py:59-100` (`authorize_page`), `app/routers/oauth2.py:200-330` (`authorize_grant`)
**Severity:** Low
**OWASP Category:** A01:2021 - Broken Access Control

**Description:** `authorize_page` and `authorize_grant` validate the client's existence, `client_type`, and `redirect_uri`, but never check `is_active`. Only `token_endpoint` checks it (`app/routers/oauth2.py:389`). A deactivated OAuth2 client therefore still renders a WeftID-branded consent page, and a user who approves it receives a real authorization code redirected to the client's registered URI.

**Attack Scenario:** An admin deactivates a compromised or decommissioned app, expecting it to be inert. The app's authorize URL keeps working: users are shown a legitimate-looking WeftID consent screen naming the app, approve it, and a valid authorization code is delivered to the (possibly attacker-controlled, since the app was deactivated for a reason) registered redirect URI. The code cannot be exchanged — `token_endpoint` rejects the deactivated client with `invalid_client` — so this is not a token-issuance bypass. What it is: a live consent-phishing surface on a client the admin believes is off, plus a code leaked to a redirect URI that is no longer trusted. For an OIDC-enabled client the deactivation is additionally not audited as a denial, since `oidc_access_denied` never fires.

**Exploitability:** Moderate (requires a user to approve; requires the deactivated client's redirect URI to still be attacker-reachable).
**Impact:** Consent phishing under WeftID branding; authorization code disclosure to an untrusted endpoint. Contained by the token endpoint's check.

**Remediation:** Check `is_active` in `authorize_page` alongside the existing `client_type` check, and again in `authorize_grant` (defense in depth, matching the pattern already used for the OIDC group check):

```python
# app/routers/oauth2.py, authorize_page, after the client_type check
if not client.get("is_active", True):
    return templates.TemplateResponse(
        request,
        "oauth2_error.html",
        {
            "error": "Unauthorized client",
            "error_description": "This client is not authorized for this flow.",
            "nav": {},
            "csp_nonce": get_csp_nonce(request),
        },
    )
```

Keep the error text identical to the existing `client_type` rejection so the page does not disclose whether a given `client_id` exists-but-is-deactivated versus is-the-wrong-type. In `authorize_grant`, redirect with `error=unauthorized_client` as that branch already does for the `client_type` failure.

**Files Affected:** `app/routers/oauth2.py`, tests

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

## [BUG] Upload routes leak the parsed file when super-admin check rejects

**Discovered:** 2026-06-20 (surfaced by enabling `filterwarnings = ["error"]`)
**Severity:** Low (no production impact; currently warning-ignored + tracked)
**Source:** pytest `PytestUnraisableExceptionWarning` (`SpooledTemporaryFile.__del__`)

On routes that take an `UploadFile` under a router-level `require_super_admin`
dependency, FastAPI parses (buffers) the multipart body before the dependency
runs. When the dependency rejects, the file param is never bound, so its
`SpooledTemporaryFile` is never closed and is reclaimed only at GC, where
`__del__` raises an unraisable exception. In tests this attaches
non-deterministically to whatever test is running and fails the suite under
error-mode warnings.

**Impact:** None in production (small in-memory temp file, GC-time noise). The
only observable effect is the test warning.

**Current handling:** A narrowly-scoped `filterwarnings` ignore in
`pyproject.toml` (matched to the `SpooledTemporaryFile` message only) keeps the
suite warning-clean. This is a deliberate, documented exception to the
warnings-are-errors policy.

**Real fix (deferred):** Restructure super-admin-guarded upload routes so the
body is not buffered before the access check (e.g. in-handler auth for upload
routes, or a mechanism that closes form files on dependency rejection). The
obvious fix (parse the form after the auth check via `async with request.form()`)
collides with the CSRF middleware, which already owns multipart body parsing, so
this needs a coordinated change. When fixed, remove the `filterwarnings` ignore.

**Files Affected:** `app/routers/saml_idp/admin.py` (and the other 5 `UploadFile`
routes share the latent pattern), `app/middleware/csrf.py`, `pyproject.toml`

---

## [DEPS] pygments 2.19.2 — CVE-2026-4539 (LOW, blocked by upstream)

**Discovered:** 2026-05-12, re-confirmed 2026-05-15
**Severity:** Low
**Source:** `python dev/deps_check.py`

**CVE-2026-4539** (GHSA-5239-wwwm-4pmq): ReDoS in `AdlLexer`
(`pygments/lexers/archetype.py`).

**Exploitability in this project: NONE.** Pygments is only used to
syntax-highlight code blocks in the docs site (built at image time, not
user-facing input). No Adl/archetype files are rendered.

**Remediation: BLOCKED.** Pinned `<2.20` in `pyproject.toml` because
`pymdownx.superfences` (via `zensical`) crashes on pygments 2.20.0
(`filename=None` regression). Wait for an upstream `pymdownx.superfences`
fix or swap to the new API before bumping.

Does not block `make check` (deps_check only fails on critical/high).

**Files Affected:** `pyproject.toml`, `poetry.lock`

---
