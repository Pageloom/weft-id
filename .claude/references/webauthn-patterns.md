# WebAuthn / Passkey Security Patterns

Reference for `/security` when reviewing any code under `app/services/webauthn.py`,
`app/utils/webauthn.py`, `app/routers/**/passkey*`, `app/routers/auth/enhanced_enrollment.py`,
`app/database/webauthn_credentials.py`, `app/schemas/webauthn.py`, or
`db-init/migrations/*webauthn*.sql`.

## 1. User Verification (UV) must match the policy promise

**Red Flag:**
```python
# VULNERABLE - UV is only preferred, verification does not require it
authenticator_selection=AuthenticatorSelectionCriteria(
    user_verification=UserVerificationRequirement.PREFERRED,
)
# ...later...
verify_authentication_response(..., require_user_verification=False)
```

A passkey without UV is "something you have" only. If the tenant auth-strength
policy treats a passkey as satisfying strong/MFA sign-in (single-step phishing-
resistant), UV must be **REQUIRED** at registration AND at verification. An
authenticator left unlocked on a desk otherwise completes sign-in.

**Checklist:**
- [ ] `generate_registration_options` sets `user_verification=REQUIRED` (or the stored credential carries a `uv=True` flag that is checked before counting it toward policy strength).
- [ ] `generate_authentication_options` sets `user_verification=REQUIRED`.
- [ ] `verify_authentication_response` is called with `require_user_verification=True`.
- [ ] Whatever policy code grants "strong auth" credit to a passkey reads the same flag it enforced at registration.

## 2. RP ID and origin derivation must be bound to tenant, not headers

**Red Flag:**
```python
def rp_id_for_request(request):
    # Trusts whatever the reverse proxy (or direct caller!) puts in these headers
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    return normalize_host(host)
```

If the app port is ever exposed directly (debug, internal network, misconfigured
compose override), an attacker can spoof `X-Forwarded-Host` to scope a passkey
registration to any RP ID they like, then phish.

**Checklist:**
- [ ] RP ID derives from the tenant record (`tenant.subdomain + BASE_DOMAIN`) or a server-side allowlist, not from request headers.
- [ ] Expected origin for verification is computed from the same server-side source.
- [ ] If header-derived values are kept, a `TRUSTED_PROXIES` allowlist gates `X-Forwarded-*` usage.

## 3. Challenge binding and replay

**Checklist:**
- [ ] Challenge bytes are stored server-side (session / cache), not round-tripped through a client cookie or hidden form field.
- [ ] TTL is enforced (5 min is typical; longer windows widen the replay surface).
- [ ] Session keys for the ceremony are cleared on success AND on every failure branch.
- [ ] Post-success code path regenerates the session (prevents fixation by challenge-reuse).
- [ ] The user bound to the ceremony at `begin` is re-validated at `complete` (not inactivated, not IdP-linked, etc.).

## 4. Credential identity binding

**Red Flag:** Matching the returned assertion against any credential in the DB
rather than credentials the bound user owns.

**Checklist:**
- [ ] `allowCredentials` at begin time is scoped to the pending user, not open ("discoverable") unless that is deliberate.
- [ ] At complete time, the returned `rawId` is looked up within the pending user's credentials, not globally.
- [ ] DB queries for update / delete / rename include `user_id` in the `WHERE` clause (defence-in-depth against cross-user credential manipulation even if the service check is wrong).

## 5. Sign-count and clone detection

**Checklist:**
- [ ] Sign-count regression raises a distinct error and deletes (or flags) the credential.
- [ ] For `backup_eligible=True` synced credentials, the verifier is fed `0` (or the check is otherwise relaxed) because sync resets the counter legitimately.
- [ ] Clone suspicion emits an audit event (`passkey_auth_failure` reason=`clone_suspected`).

## 6. Ceremony payload size

**Red Flag:**
```python
class CompleteAuthenticationRequest(BaseModel):
    response: dict  # Unbounded JSON - pre-auth DoS surface
```

`request.json()` reads the entire body into memory before Pydantic sees it.
Combined with no proxy-level body cap, an attacker can spray MBs per request.

**Checklist:**
- [ ] Reverse proxy or ASGI middleware caps request body size (1 MiB global, 128 KiB for JSON auth endpoints is a reasonable starting point).
- [ ] Ceremony schemas use a typed `PublicKeyCredentialResponse` sub-model with per-field `max_length`, not bare `dict`.
- [ ] `rawId`, `clientDataJSON`, `attestationObject`, `authenticatorData`, `signature`, `userHandle` each have explicit length caps.

## 7. Admin revocation = compromised-credential path

**Checklist:**
- [ ] Admin-revoke path revokes OAuth2 tokens / sessions as well (holding a stolen passkey usually implies a live stolen session too).
- [ ] A plain admin cannot revoke a super_admin's passkey (role check exists).
- [ ] Admin cannot revoke their own passkey via the admin surface (force self-service path for auditability).
- [ ] Revocation emits an audit event distinguishable from self-deletion (e.g. `metadata.revoked_by_admin=True`, `target_user_id`, `target_user_name`) since the target's name may be anonymized later.

## 8. Backup codes / recovery interplay

**Checklist:**
- [ ] Backup codes are issued at most once on first passkey registration if none exist; never re-issued silently.
- [ ] Deleting the last passkey does not leave the user without any sign-in factor when the tenant policy requires a strong factor (handled by policy re-evaluation on next login, not by blocking delete).
- [ ] Passkey registration + TOTP + email OTP backup codes share the same backup-code pool or are deliberately kept separate; the choice is documented.

## 9. Enumeration / oracle surfaces

**Checklist:**
- [ ] `begin-authentication` returns identical 404 / "not eligible" for: nonexistent email, IdP-linked user, inactivated user, zero-passkey user.
- [ ] Login page rendering does not branch on "user has passkey" unless that branch is reachable via the same oracle the attacker can already hit (e.g. `begin-authentication`).
- [ ] Rate limits on `begin` and `complete` share a counter with the password flow so passkey attempts cannot dodge the global login-block budget.

## 10. Session gates for pre-auth flows

**Checklist:**
- [ ] Enhanced-enrollment flow is gated by a session key (`pending_enhanced_enrollment_user_id`) set only after baseline auth succeeded.
- [ ] The gate key is cleared on every exit (success, failure, timeout).
- [ ] Between `begin` and `complete`, the bound user is re-fetched and re-validated (inactivation, IdP-link, deletion since `begin`).
