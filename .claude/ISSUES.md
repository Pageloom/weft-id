# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 2 | File Structure (pre-existing); Mirrored-attr scrub skips per-user IdP disconnect |
| Low | 3 | Test coverage (E2E anchor, deferred); Upload-auth temp-file leak (warning-ignored, tracked); Security defense-in-depth bundle (5 items) |
| Compliance | 6 | Audit-trail gaps (SCIM reactivation, protected-domain verify-failed, no-op settings event, WebAuthn revoke actor); latent UNSCOPED WITH CHECK; migration 0034 numbering/comment |
| Deps | 1 | pygments (LOW, blocked by upstream) |

Note: the six inbound-SCIM final-review items (cross-IdP rebind audit event, actor
consistency, private-helper import boundary, `list_active_tokens` dead code, canonical-email
validation, Pydantic `max_length`) plus the project-wide proxy-headers / forwarded-host trust
boundary were resolved on the inbound-scim branch (2026-05-29); see ISSUES_ARCHIVE.md.

**Last security scan:** 2026-06-21 (targeted 60-day sweep of forward-auth proxy, inbound/outbound SCIM, WebAuthn, and user-attributes→SAML flow; forward-auth, inbound SCIM, and WebAuthn verified well-defended; 1 HIGH SSRF + 2 MEDIUM attribute-provenance + Low DiD bundle logged below)
**Last compliance scan:** 2026-06-21 (automated checker clean, 0 violations across 1612 files; targeted 60-day manual sweep of SCIM, WebAuthn, attributes/auth-policy/settings, forward-auth proxy, and migrations 0031-0048; 6 warning-level judgment findings logged below, no blockers)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-06-20 (cryptography 48.0.0→48.0.1, python-multipart 0.0.29→0.0.31, pip 26.1.1→26.1.2, msgpack 1.1.2→1.2.1, starlette 1.0.1→1.3.1 bumped, clearing all 6 HIGH/MED CVEs; full suite green; pygments still pinned `<2.20`, see [DEPS] entry below)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-24 (terminology sweep: "two-step verification" → "sign-in strength" / "sign-in methods" where passkeys make "two-step" inaccurate)

---

## [SECURITY] Stale mirrored attributes retained on per-user IdP disconnect

**Found in:** `app/services/saml/domains.py:424-498` (`assign_user_idp`); contrast scrub at `app/services/saml/providers.py:382-408` (`delete_identity_provider` only)
**Severity:** Medium
**OWASP Category:** A01:2021 - Broken Access Control (stale authorization data)
**Description:** The opt-in scrub of mirrored attributes (commit 93a98fd) is wired only into the bulk **IdP-delete** path (`_scrub_canonical_matches_mirror`). But an IdP cannot be deleted while any user is assigned (`providers.py:348-356`), so the realistic disconnect is `assign_user_idp(user, saml_idp_id=None)` (admin converts a user to password-only). That path inactivates the user and unverifies emails but never touches `user_attributes` / `user_idp_attributes`.
**Attack Scenario:** A user disconnected from IdP A (or moved to IdP B) keeps the canonical attributes last mirrored from IdP A. On reactivation as a password user or re-IdP, those stale values (e.g. `department`, `employee_id`) continue to be emitted in assertions to SPs, with no provenance, indefinitely. `mirror_from_idp` defaults to true, maximizing how many values get mirrored in the first place.
**Evidence:** `grep` shows `_scrub_canonical_matches_mirror` is referenced only from `delete_identity_provider`; `assign_user_idp` (`domains.py:424`) has no `user_attributes`/`user_idp_attributes` cleanup.
**Impact:** Departed-IdP attribute values keep flowing to downstream SPs; compounds the spoofing/trust issue above.
**Remediation:** Offer the same opt-in scrub on `assign_user_idp` when `saml_idp_id` transitions to `None` or to a different IdP, clearing canonical rows still matching the old IdP's mirror snapshot, emitting `user_profile_updated` with `cause=idp_disconnect_scrub` to mirror the existing delete-path behavior.

**Files Affected:** `app/services/saml/domains.py`, `app/services/saml/providers.py`, `app/services/users/attributes.py`

---

## [SECURITY] Defense-in-depth bundle (Low) — 5 hardening items

**Discovered:** 2026-06-21 (60-day targeted sweep)
**Severity:** Low (each individually mitigated by another control; logged for hardening)
**OWASP Category:** Mixed (A05 / A08 / A09 / resource exhaustion)

> Item 1 (outbound SCIM redirect-following implicit) was resolved 2026-06-21:
> `build_safe_client` now sets `follow_redirects=False` explicitly. See
> ISSUES_ARCHIVE.md (SSRF guard). Remaining items below.

Each item is currently mitigated, but worth closing as defense-in-depth:

1. **Inbound SCIM bearer not length-capped pre-hash.** `app/api_dependencies.py:255` hashes the raw `Authorization` token with no length bound before `sha256`; oversized-header defense relies on the reverse proxy. Reject `len(token) > ~512` before hashing on this pre-auth path. (A04)
2. **Inbound SCIM `members[]` array unbounded.** `app/services/scim/inbound_group_write.py` bounds membership only by the global 1 MiB body cap; a ~1 MiB `members[]` PUT triggers O(N) per-member DB lookups on an authenticated endpoint. Add a per-request member ceiling. (Resource exhaustion)
3. **Forward-auth cookie can scope to a public suffix.** `app/services/protected_domains.py:59-88` (`_validate_host`) has no public-suffix-list check, so a registered domain like `co.uk` would set a `Domain=co.uk` cookie (`app/utils/forward_auth.py:386`). Unreachable without DNS control of the suffix (DNS-TXT gate), but add a PSL/denylist guard. (A05)
4. **Forward-auth token `v` (version) field minted but never verified.** `app/utils/forward_auth.py:175` sets `"v": 1`; `verify_authorization_token` (`:217-242`) and `read_forward_auth_cookie` (`:321-344`) never assert it. Harmless today (HMAC covers it) but a future `v: 2` format could enable downgrade confusion. Add `if payload.get("v") != 1: return None`. (A08)
5. **WebAuthn tenant selection is header-rooted.** `rp_id_for_tenant` now reads the tenant record (c60d27e, correct), but the `tenant_id` it receives originates from `x-forwarded-host`/`host` (`app/dependencies.py:32`). Mitigated because the deploy compose never publishes the app port directly (`deploy/docker-compose.yml`), so the header is proxy-controlled. Cross-check the resolved tenant against the authenticated user's `tenant_id` in the ceremony, or assert a `TRUSTED_PROXIES` invariant, to remove the header dependency. (A05)

**Note (product decision, not a code bug):** Inbound SCIM `POST /Users` merges on primary email across IdP connections within a tenant and silently rebinds the user to the posting IdP (`app/services/scim/inbound_write.py:604-660`). It is RLS-confined to one tenant and emits a `scim_user_rebound` audit event, but the rebind is silent in the admin UI. Consider rejecting with `409` when the matched user is bound to a different IdP unless an explicit "allow cross-IdP claim" policy is enabled, and surface `scim_user_rebound` in the admin activity view.

**Files Affected:** `app/api_dependencies.py`, `app/services/scim/inbound_group_write.py`, `app/services/protected_domains.py`, `app/utils/forward_auth.py`, `app/dependencies.py`, `app/services/scim/inbound_write.py`

---

## [COMPLIANCE] SCIM-driven reactivation is not audited

**Found in:** `app/services/scim/inbound_write.py:500-502` (`_handle_active_transition`, reactivate branch)
**Severity:** Warning
**Principle Violated:** Activity/Event Logging ("if there is a write, there is a log")
**Description:** The deactivate branch (lines 489-499) emits the security-tier `scim_user_deactivated` event. The reactivate branch performs two mutations (`reactivate_user` + `clear_reactivation_denied`), re-enabling a previously disabled account, but logs no dedicated event. The umbrella `scim_user_updated` (admin-tier) fires from the caller but does not record that a disabled account was re-enabled.
**Impact:** Audit-trail asymmetry. A security filter for "account re-enabled" catches admin-driven reactivations (`user_reactivated`) and all SCIM deactivations, but silently misses every SCIM-driven reactivation. `app/constants/event_types.py` has `scim_user_deactivated` but no `scim_user_reactivated`.
**Suggested fix:** Add a `scim_user_reactivated` (security-tier) event after the reactivate mutations, mirroring the deactivate branch, and register it in `app/constants/event_types.py`:
```python
database.users.reactivate_user(tenant_id, user_id)
database.users.clear_reactivation_denied(tenant_id, user_id)
log_event(
    tenant_id=tenant_id, actor_user_id=SYSTEM_ACTOR_ID,
    artifact_type="user", artifact_id=user_id,
    event_type="scim_user_reactivated",
    metadata={"idp_id": idp_id, "cause": "scim_active_true"},
)
```
**Files Affected:** `app/services/scim/inbound_write.py`, `app/constants/event_types.py`

---

## [COMPLIANCE] WebAuthn admin token-revoke attributes the action to the target user

**Found in:** `app/services/webauthn.py:420-427` (`admin_revoke_credential`)
**Severity:** Warning
**Principle Violated:** Event Logging correctness (actor attribution)
**Description:** This is an admin action (the function established `requesting_user["id"] != user_id` at line 382), but the `oauth2_user_tokens_revoked` event sets `actor_user_id=str(user_id)` (the *target*). The sibling `passkey_deleted` event in the same function (line ~431) correctly uses `actor_user_id=str(requesting_user["id"])`. The self-service pattern (`password.py`, where actor==target legitimately) was copied without adjusting for the cross-user admin context.
**Impact:** The audit trail attributes the token revocation to the victim rather than the admin who performed it. Inconsistent actor attribution within the same function.
**Suggested fix:** Use `actor_user_id=str(requesting_user["id"])` and move the target into metadata (e.g. `"target_user_id": str(user_id)`), matching the `passkey_deleted` event in the same function.
**Files Affected:** `app/services/webauthn.py`

---

## [COMPLIANCE] protected-domain verification "failed" branch writes without a log

**Found in:** `app/services/protected_domains.py:347-349` (`verify_protected_domain`, failure branch)
**Severity:** Warning
**Principle Violated:** Activity/Event Logging ("if there is a write, there is a log")
**Description:** The success branch logs `protected_domain_verified` (lines 325-339). The failure branch flips `verification_status="failed"` (a real admin-triggered state transition) with no `log_event()`, and no `protected_domain_verification_failed` event type is registered. The idempotent "already verified" early return is a pure read and correctly logs nothing.
**Impact:** An admin-triggered state transition (pending → failed) leaves no audit trail. Low-sensitivity field and re-runnable action, hence warning not blocking.
**Suggested fix:** Add a `protected_domain_verification_failed` event type and `log_event(...)` after the failed-status update, or document this branch as an intentional exception.
**Files Affected:** `app/services/protected_domains.py`, `app/constants/event_types.py`

---

## [COMPLIANCE] update_security_settings logs a no-op audit event

**Found in:** `app/services/settings/security.py:404-412`
**Severity:** Warning
**Principle Violated:** Event Logging correctness (log reflects a real write)
**Description:** The umbrella `tenant_settings_updated` event fires unconditionally with `metadata={"changes": changes} if changes else None`, so a no-op update (re-submitting identical values) writes an audit event with `metadata=None`. The dedicated sub-events (cert lifetime, password policy, etc.) are all correctly gated on an actual diff, and the parallel `update_tenant_attribute_config` (`attributes.py:110`) correctly logs only `if changes:`.
**Impact:** No-op PATCHes pollute the audit trail with non-change events.
**Suggested fix:** Gate the umbrella event on `if changes:` to match the attribute-config pattern, or document that a "settings touched" event is intentional even on no-op.
**Files Affected:** `app/services/settings/security.py`

---

## [COMPLIANCE] Latent UNSCOPED WITH CHECK permits cross-tenant writes (hardening)

**Found in:** migrations `0037_scim_unscoped_rls.sql`, `0045_scim_inbound_tokens_unscoped_rls.sql`, `0047_protected_domains_unscoped_rls.sql`, `0048_forward_auth_nonces.sql`
**Severity:** Warning (latent — safe today)
**Principle Violated:** RLS Policy Consistency / Tenant Isolation (defense-in-depth)
**Description:** All four UNSCOPED policies use the same `CASE WHEN tenant unset THEN true` in **both** USING and WITH CHECK. Reads are correctly permissive (lookup happens before tenant scope exists, keyed on globally-unique columns / 256-bit secrets, then re-scoped). But because WITH CHECK is equally permissive, any INSERT/UPDATE run under `UNSCOPED` could silently write an arbitrary `tenant_id` rather than failing closed.
**Impact:** Safe today — all UNSCOPED write paths are DELETE-only (nonce/expiry consume) or trusted system/worker code. But a future UNSCOPED INSERT/UPDATE on any of these tables would bypass tenant isolation silently. The existing `check_scim_rls_widening_violations` scanner restricts UNSCOPED SCIM call sites but does not cover `protected_domains` or `forward_auth_nonces`.
**Suggested fix:** Make WITH CHECK stricter than USING — keep UNSCOPED reads permissive but drop the `WHEN unset THEN true` branch from WITH CHECK only, so an accidental UNSCOPED write fails closed. Apply via a new forward migration (do not rewrite applied migrations).
**Files Affected:** new migration; `dev/compliance_check.py` (optional scanner coverage for the two non-SCIM tables)

---

## [COMPLIANCE] Migration 0034 numbering gap and stale 0035 comment

**Found in:** `db-init/migrations/` (sequence skips 0033 → 0035); `0035_user_attributes_mirror_default_true.sql` header
**Severity:** Warning (documentation)
**Principle Violated:** Migration consistency
**Description:** There is no `0034` file on disk; the sequence jumps from `0033_user_attributes.sql` to `0035`. The `0035` header references "the column added in 0034," but the `mirror_from_idp` column it alters actually lives in `0033`. No runtime impact (the runner tracks applied versions via `schema_migration_log`), but the numbering gap and stale comment are confusing.
**Impact:** Documentation drift; potential confusion if any environment recorded a `0034` in `schema_migration_log`.
**Suggested fix:** Confirm 0034 was intentionally collapsed into 0033; correct the `0035` header comment to reference `0033`; verify no environment has a `0034` row in `schema_migration_log`.
**Files Affected:** `db-init/migrations/0035_user_attributes_mirror_default_true.sql`

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

## [TEST] Regression anchor for user_attributes feature (E2E, deferred)

**Discovered:** 2026-05-14 (test agent final-pass review)
**Severity:** Low (deferred regression coverage)
**Source:** Test review (M-test1 + L bundle)

Five of the six original anchors landed on feature/forward-auth-proxy (2026-06-16);
see ISSUES_ARCHIVE.md. One remains, deferred because it needs Playwright + Docker:

- E2E for admin → user fills → SP receives (full cross-iteration journey)

**Files Affected:** `tests/e2e/`

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
