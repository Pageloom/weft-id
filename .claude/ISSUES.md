# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Medium | 2 | File Structure (pre-existing), Proxy headers / forwarded-host trust boundary (project-wide) |
| Low | 8 | Duplication (pre-existing), Docs (pre-existing), Test coverage (pre-existing), SCIM cross-IdP rebind audit gap, SCIM Pydantic max_length, SCIM `list_active_tokens` dead code, SCIM canonical-email validation, SCIM private-helper import boundary, SCIM audit actor consistency |
| Deps | 1 | pygments (LOW, blocked by upstream) |

Note: the SCIM-group-rename trigger gap surfaced by iteration 4's test agent was fixed in the
same iteration; see ISSUES_ARCHIVE.md for the entry.

**Last security scan:** 2026-05-15 (mirror-failure audit event + user_profile_updated PII redaction landed on feature/user-attributes; remaining low items unchanged)
**Last compliance scan:** 2026-04-13 (all clear, 15 checks; re-verified during security/april-2026-sweep branch)
**Last API coverage audit:** 2026-04-23 (3 gaps resolved: group clear relationships, IdP reimport XML, SAML debug entries)
**Last dependency audit:** 2026-05-15 (python-multipart, urllib3, pip bumped; pygments still pinned `<2.20`, see [DEPS] entry below)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-24 (terminology sweep: "two-step verification" → "sign-in strength" / "sign-in methods" where passkeys make "two-step" inaccurate)

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


## [DOCS] API endpoint docstring claims "super_admin only" but service is relaxed

**Discovered:** 2026-05-14 (security agent final-pass review L3)
**Severity:** Low (cosmetic)
**Source:** Security review L3

`list_tenant_attribute_config` was deliberately relaxed to any authenticated user during iter 7 so the force-completion gate is escapable for non-admin users. The API endpoint `GET /api/v1/tenant/attribute-config` is still super-admin-gated at the router layer, but the service docstring previously documented "super_admin only." Verify and update docstring wording.

**Files Affected:** `app/services/settings/attributes.py`, `app/routers/api/v1/settings.py`

---

## [TEST] Regression anchors for user_attributes feature

**Discovered:** 2026-05-14 (test agent final-pass review)
**Severity:** Low (deferred regression coverage)
**Source:** Test review (M-test1 + L bundle)

Useful regression anchors, none are current bugs:

- E2E for admin → user fills → SP receives (full cross-iteration journey)
- `apply_idp_attributes` "overwrites user-set canonical value when mirror=on" explicit test
- `apply_idp_attributes` "preserves unrelated canonical rows" explicit test
- Dashboard banner empty-case test (`missing_required == []`)
- JIT-provisioned user mirror-failure path (sibling to existing existing-user test)
- Admin user-detail route integration test for `user_profile_updated` event emission

**Files Affected:** `tests/services/test_saml_attribute_ingestion.py`, `tests/services/test_user_attributes_service.py`, `tests/routers/test_auth.py`, `tests/routers/test_user_detail_profile.py`, `tests/e2e/`

---

## [SECURITY] Proxy headers + x-forwarded-host trust boundary (project-wide)

**Discovered:** 2026-05-28 (inbound-SCIM final review: security agent S1+S3 and test agent T3)
**Severity:** Medium
**Source:** Inbound SCIM final review (rate-limit + URL coherence)

Two related issues with the same root cause:

1. **Rate-limit bucket effectively global behind the proxy.** `request.client.host` is the proxy IP (nginx in dev, Caddy in prod) because uvicorn isn't started with `--proxy-headers --forwarded-allow-ips=<proxy-net>`. The 60/min inbound-SCIM bucket can be exhausted by a single hostile public IP, denying real Okta/Entra ingress until the window expires. Same root affects every other per-IP rate-limited endpoint in the app.
2. **`x-forwarded-host` trusted without a boundary** (`app/utils/urls.py:19-27`, `app/routers/saml/admin/inbound_scim.py:48-49`). Inbound-SCIM `meta.location` URLs are derived from the request host; an attacker who can spoof the header can render URLs pointing at a different tenant subdomain. Data isolation holds (RLS), URL coherence does not.

**Remediation:** Configure uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy-net>` (or install a Starlette `ProxyHeadersMiddleware`). Then derive host from a trusted-proxy-aware layer rather than the raw header. Project-wide payoff, not just inbound SCIM.

**Files Affected:** `Dockerfile`, `app/Dockerfile`, `dev/docker-compose.yml`, `app/main.py`, `app/utils/urls.py`, `app/api_dependencies.py`

---

## [SECURITY] Inbound SCIM cross-IdP rebind has no dedicated audit event

**Discovered:** 2026-05-28 (inbound-SCIM final review: test agent T2, security agent S2)
**Severity:** Low
**Source:** Inbound SCIM final review

Iteration 3 deliberately allows POST to IdP-B for a canonical email already bound to IdP-A: WeftID rebinds the user to IdP-B silently and emits only `scim_user_received` with `metadata.merged=true`. Within tenant a compromised IdP-A token can rebind users to itself; the audit-trail entry doesn't surface "this user was previously bound to IdP-X." Behaviour is pinned by `test_cross_idp_email_match_rebinds_user_to_new_idp`.

**Remediation:** Either (a) emit a dedicated `scim_user_rebound` event from `_create_or_merge_user_attempt` when `set_user_idp` actually changes the binding, or (b) add `previous_idp_id` to the `scim_user_received` metadata when `merged=true`. Option (a) gives operators a clean filter for forensics.

**Files Affected:** `app/services/scim/inbound_write.py`, `app/constants/event_types.py`

---

## [REFACTOR] Inbound SCIM group write imports private helpers from services.groups.idp

**Discovered:** 2026-05-28 (inbound-SCIM final review: compliance agent C1)
**Severity:** Low
**Source:** Compliance review

`app/services/scim/inbound_group_write.py:51-55` imports `_apply_membership_additions` and `_apply_membership_removals` (underscore-prefixed) from `services.groups.idp`. The behaviour is correct (DB calls + `idp_group_member_added`/`removed` events gated by `system_context()`), but the cross-module private import erodes the module-private convention.

**Suggested Refactoring:** Promote both helpers to public names in `services.groups.idp` (`apply_membership_additions` / `apply_membership_removals`) or extract a shared `services.groups.membership_helpers` module.

**Files Affected:** `app/services/scim/inbound_group_write.py`, `app/services/groups/idp.py`

---

## [REFACTOR] Inbound SCIM write events use inconsistent actor_user_id

**Discovered:** 2026-05-28 (inbound-SCIM final review: compliance agent C3)
**Severity:** Low
**Source:** Compliance review

SCIM user-write events in `app/services/scim/inbound_write.py` log `actor_user_id=user_id` (the affected user); group-write events in `app/services/scim/inbound_group_write.py` log `actor_user_id=SYSTEM_ACTOR_ID`. The actor for inbound SCIM is the upstream IdP, not the user being modified. The audit log otherwise reads as "user X deactivated themselves."

**Remediation:** Standardise on `SYSTEM_ACTOR_ID` for user-write events too (metadata already carries `idp_id`).

**Files Affected:** `app/services/scim/inbound_write.py`

---

## [REFACTOR] Inbound SCIM `list_active_tokens` is dead code

**Discovered:** 2026-05-28 (inbound-SCIM final review: test agent Gap E)
**Severity:** Low
**Source:** Test review

`app/database/scim_inbound_tokens.py:82-94` defines `list_active_tokens` which is tested but has no production caller (the admin tab uses `list_tokens` which includes revoked rows). Either delete or wire into the admin tab to hide revoked rows from the active list.

**Files Affected:** `app/database/scim_inbound_tokens.py`

---

## [TEST] Inbound SCIM canonical-email validation when userName is not an email

**Discovered:** 2026-05-28 (inbound-SCIM final review: test agent Gap F)
**Severity:** Low
**Source:** Test review

`_canonical_email` in `app/services/scim/inbound_write.py:160` falls back to `userName` even when it's not an email. If Okta sends `userName="alice.smith"`, that string ends up as `user_emails.email`. The `citext` column accepts it but the user now has a non-email "email." Likely the same gap exists in `services.saml.provisioning.jit_provision_user`.

**Remediation:** Validate email format before storage, or document this fallback behaviour and align SCIM with JIT.

**Files Affected:** `app/services/scim/inbound_write.py`, `app/services/saml/provisioning.py`

---

## [TEST] Inbound SCIM Pydantic write models lack max_length

**Discovered:** 2026-05-28 (inbound-SCIM final review: compliance agent C2)
**Severity:** Low
**Source:** Compliance review

`ScimUserWrite`, `ScimGroupWrite`, `ScimPatchRequest` in `app/schemas/scim.py:213-252` lack `max_length` on string fields. Currently dormant because the routers accept raw `dict[str, Any]` bodies (Caddyfile enforces 1MB per route). If a future iteration switches to typed bodies for stricter validation, every str field needs `max_length` added.

**Remediation:** Preventive hardening: add `max_length` now so the models are ready to be wired in safely.

**Files Affected:** `app/schemas/scim.py`

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
