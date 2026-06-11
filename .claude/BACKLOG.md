# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Drop SendGrid Email Backend; Add Amazon SES and Postmark

**User Story:**
As a WeftID operator (hosted or self-hosting),
I want SendGrid removed and Amazon SES and Postmark offered alongside SMTP and Resend,
So that I can pick a well-maintained, strong-deliverability transactional email provider and we no longer ship an unmaintained dependency.

**Context:**

Email transport lives in `app/utils/email_backends/` as a clean `EmailBackend` Protocol (`base.py`) with thin (~40-line) adapters selected at runtime by the `EMAIL_BACKEND` env var via `get_backend()` in `__init__.py`. Today the choices are `smtp` (default, universal fallback), `resend`, and `sendgrid`.

SendGrid's Python library (`sendgrid`, owned by Twilio) is effectively in maintenance-drift, and SendGrid's transactional deliverability reputation has eroded relative to peers. Because each adapter is a disposable shim touching only `from`/`to`/`subject`/`html`/`text`, swapping providers is cheap. This item removes SendGrid entirely and adds two stronger transactional standards:

- **Amazon SES** — durable, cheap, AWS-backed longevity; good fit for self-hosters already on AWS.
- **Postmark** — best-in-class *transactional* deliverability (transactional and bulk streams are hard-separated); strong thematic fit for an identity product where "the verification code email must arrive" is the whole job.

SMTP and Resend are retained.

**Design Notes:**

- **SES has two integration paths; decide deliberately:**
  - *SMTP interface* — SES exposes `email-smtp.<region>.amazonaws.com:587` (STARTTLS) using SES-specific SMTP credentials (distinct from AWS IAM keys). This works through the **existing SMTP backend with zero new code or dependencies**; an operator just points `SMTP_HOST`/`SMTP_USER`/`SMTP_PASS` at SES. At minimum, **document this path** in the self-hosting guide.
  - *Native API* — a `ses` backend via `boto3` (SESv2 `send_email`) with IAM auth, no SMTP credentials to manage, and structured error/bounce handling. Adds a `boto3` dependency (not currently present).
  - Recommendation: add the native `ses` API backend for parity with the other API backends *and* document the SMTP-interface path for operators who don't want the boto3 dependency or prefer SMTP credentials. (Final call can be made during grooming.)
- **Postmark** has no official maintained Python SDK worth coupling to; implement as a raw `requests.post` to `https://api.postmarkapp.com/email` with `X-Postmark-Server-Token`, mirroring the lean style of the existing adapters. No new heavyweight dependency.
- Extend `get_backend()` with `ses` and `postmark` branches (lazy import, matching the existing pattern); remove the `sendgrid` branch.
- New settings: `POSTMARK_SERVER_TOKEN`, and for native SES the AWS region/credentials (`AWS_REGION` plus standard boto3 credential resolution). Remove `SENDGRID_API_KEY`. Keep `FROM_EMAIL` shared.
- **`verify_email.py` CLI:** update the `_DKIM_SELECTORS` map — remove the `sendgrid` selectors (`s1`, `s2`, `smtpapi`); add `ses` (`amazonses`) and `postmark` (`pm`, plus Postmark's rotating DKIM). Keep the per-backend test-send and DKIM-probe flow working for the new backends.
- **`dev/compliance_check.py`:** remove the `SendGridAPIClient` no-timeout rule; add equivalent outbound-timeout enforcement for the new clients (boto3 SES config timeout; the Postmark `requests.post` must pass a `timeout=`).
- Enforce an outbound request timeout on both new backends (the codebase flags clients with no built-in timeout).
- Update tests in `tests/utils/test_email_backends.py` and `tests/cli/test_verify_email.py`: drop SendGrid cases, add SES and Postmark cases (success, failure, timeout, text+html).

**Removal checklist (SendGrid references to purge):**
- [ ] `app/utils/email_backends/sendgrid_backend.py` (delete)
- [ ] `app/utils/email_backends/__init__.py` (remove `sendgrid` branch)
- [ ] `app/utils/email.py` (docstring backend list)
- [ ] `app/settings.py` (`SENDGRID_API_KEY`, `EMAIL_BACKEND` comment)
- [ ] `app/cli/verify_email.py` (DKIM selectors)
- [ ] `dev/compliance_check.py` (SendGrid timeout rule)
- [ ] `pyproject.toml` + `poetry.lock` (remove `sendgrid` dep; mypy override module list)
- [ ] `deploy/prod_requirements.lock.txt`, `deploy/docker-compose.yml`, `deploy/.env.example`
- [ ] `dev/.env.example`
- [ ] `docs/self-hosting/index.md`
- [ ] `tests/utils/test_email_backends.py`, `tests/cli/test_verify_email.py`

**Acceptance Criteria:**
- [ ] SendGrid is fully removed: no `sendgrid` dependency, adapter, setting, DKIM selector, compliance rule, env example, or docs reference remains (grep for `sendgrid` is clean outside `BACKLOG_ARCHIVE.md`/`ISSUES_ARCHIVE.md`/`tech_writer_log.md` history)
- [ ] `EMAIL_BACKEND=postmark` sends via Postmark (raw HTTPS, server-token auth, enforced timeout); success and failure return correct booleans and log appropriately
- [ ] `EMAIL_BACKEND=ses` sends via Amazon SES native API (boto3 SESv2, IAM auth, enforced timeout); success and failure handled like the other adapters
- [ ] The self-hosting guide documents using **SES via the existing SMTP backend** (SES SMTP endpoint + SES SMTP credentials) as a no-new-dependency option, alongside the native `ses` and `postmark` backends and the retained `resend`
- [ ] `get_backend()` resolves `smtp`, `resend`, `ses`, `postmark`; unknown values fall back to SMTP (existing behavior preserved)
- [ ] `verify_email.py` test-send and DKIM probe work for `ses` and `postmark`; SendGrid selectors removed
- [ ] `dev/compliance_check.py` no longer references SendGrid; both new backends pass the outbound-timeout rule
- [ ] Tests cover Postmark and SES backends (success, provider error, timeout, html-only and html+text); SendGrid tests removed; full suite green
- [ ] `deploy/.env.example` and `dev/.env.example` document `ses` and `postmark` options and their required settings

**Effort:** M
**Value:** Medium (removes an unmaintained dependency and upgrades the transactional-email standards offered; no new end-user capability)
**Version impact:** Minor (additive backends, new env vars). **Breaking caveat:** any deployment currently running `EMAIL_BACKEND=sendgrid` must migrate to another backend before upgrading; call this out in CHANGELOG/release notes and the self-hosting upgrade guidance.

---

## Optional Authentik Interop SCIM E2E Tests (Inbound + Outbound)

**User Story:**
As a WeftID maintainer,
I want opt-in E2E tests that run WeftID's inbound and outbound SCIM against a real Authentik instance,
So that I have a real-world interoperability baseline proving WeftID provisions to, and accepts provisioning from, an independent SCIM 2.0 implementation, not just its own.

**Context:**

The closed-loop tests prove WeftID is self-consistent; they cannot catch divergence from how real receivers and senders interpret the spec. We already have testbed scripting (`dev/scim-testbed.sh`, `dev/scim-testbed.md`, `make scim-testbed-{up,down,destroy,status,logs,info}`) that bootstraps a local Authentik instance outside the repo, currently exercised **manually** for the outbound direction (WeftID → Authentik SCIM Source). This item automates both directions and makes them runnable as E2E tests.

- **Outbound:** WeftID pushes to an Authentik SCIM Source; assert the users/groups land in Authentik (via Authentik's API).
- **Inbound:** Authentik (configured with a SCIM Provider/application targeting WeftID's inbound SCIM endpoint) provisions into WeftID; assert the users/groups land in WeftID.

Because these require Authentik running, they must be **opt-in**: skipped by default and only collected when the testbed is reachable and an explicit env flag is set (mirroring how the suite already skips when MailDev is unavailable). They are not expected to run in default CI.

**Design Notes:**

- Gating: skip unless Authentik is reachable AND an explicit flag (e.g. `SCIM_INTEROP=1`) is set, so a stray local testbed never makes the default suite depend on it. Reuse the existing `pytest_collection_modifyitems` skip pattern in `tests/e2e/conftest.py`.
- Authentik setup should be as automated as practical via Authentik's API (create the SCIM Source for the outbound target and the SCIM Provider + application for the inbound direction, retrieve the bearer tokens) so the test can self-configure after `make scim-testbed-up`. Where full automation isn't feasible, document the manual bootstrap and read tokens/URLs from env.
- The `host.docker.internal` host is already allowed by the SSRF guard in `IS_DEV` mode (the testbed depends on it); the inbound direction needs Authentik to reach WeftID's inbound endpoint on the host.
- Outbound assertions query Authentik's API (`GET /Users`, `GET /Groups`); inbound assertions query WeftID (DB or API) for the provisioned resources and confirm `group_type='idp'` / soft-delete semantics.

**Acceptance Criteria:**

- [ ] New E2E module(s) (e.g. `tests/e2e/test_scim_authentik_interop_e2e.py`) covering both directions against the Authentik testbed
- [ ] Tests are **skipped by default**; collected only when Authentik is reachable and an explicit opt-in flag (e.g. `SCIM_INTEROP=1`) is set
- [ ] **Outbound:** a WeftID group grant/membership change provisions users and groups into Authentik; asserted via Authentik's API (POST then PUT then DELETE lifecycle)
- [ ] **Inbound:** Authentik provisions users and groups into WeftID via the inbound SCIM endpoint; asserted in WeftID (users active, groups `group_type='idp'`, removal soft-deletes)
- [ ] Authentik source/provider/token setup automated via its API where feasible; manual fallback documented and read from env
- [ ] A `make` target or helper to provision the Authentik objects and surface the tokens/URLs the tests consume (extends the existing `scim-testbed` tooling)
- [ ] `dev/scim-testbed.md` updated to document running the interop tests (env flag, setup, both directions, that CI does not run them)
- [ ] Clear skip message when the opt-in flag/testbed is absent (no silent pass, no hard failure)

**Effort:** L
**Value:** Medium-High (real interoperability baseline against an independent SCIM implementation; catches spec-interpretation drift the closed-loop tests cannot)
**Version impact:** None (test infrastructure only)

**Dependencies:** Inbound SCIM ✅ and Outbound SCIM ✅ shipped; builds on the existing `dev/scim-testbed.sh` Authentik tooling. Complements (does not replace) the closed-loop item above.

---

## Docs: capture SCIM admin guide screenshots

**Status:** Backlog

**Summary:** `docs/admin-guide/service-providers/scim.md` ships with `TODO: screenshot - ...` placeholders at six locations (amber plaintext token box, credential list mid-rotation, sync activity panel mixed states, Slack provisioning page, GitHub Enterprise SCIM page, Atlassian directory provisioning, GitLab SAML SSO page). Capture the WeftID screenshots first (amber box, credential list, sync panel) since they can be staged against the dev testbed. Vendor screenshots require live tenants and can land later as access becomes available. Remove the `TODO:` lines once each image lands.

**Effort:** S
**Value:** Medium (lifts the docs above placeholder quality for outbound SCIM)

---

## Custom User Fields

**Status:** Grooming

**Summary:** Admin-defined custom fields on user profiles. Supported types: one-line text, multiline text, single-select, multi-select, currency, time, duration, date, datetime.

**Effort:** XL
**Value:** High

---

## Create `/accessibility` Skill

**User Story:**
As a developer,
I want an `/accessibility` skill that audits the frontend for WCAG 2.1 AA compliance,
So that accessibility issues are identified and tracked systematically like security and compliance violations.

**Acceptance Criteria:**

- [ ] New skill file at `.claude/skills/accessibility/` following the pattern of existing skills
- [ ] Skill audits Jinja2 templates for WCAG 2.1 AA violations (missing alt text, insufficient contrast cues, missing form labels, ARIA misuse, keyboard navigation gaps, missing lang attributes, missing focus indicators)
- [ ] Skill logs findings to `ISSUES.md` in the same format as `/security` and `/compliance`
- [ ] Skill references a checklist in `.claude/references/wcag-patterns.md`
- [ ] Skill can be invoked with `/accessibility` from Claude Code

**Effort:** M
**Value:** Medium

---

## Dyslexic-Friendly Font User Preference

**User Story:**
As a user with dyslexia,
I want to enable a dyslexic-friendly font in my account settings,
So that the interface is more readable for me without affecting other users.

**Acceptance Criteria:**

- [ ] A font preference field is added to the user profile (boolean, default false)
- [ ] Database migration adds the column to the `users` table
- [ ] User can toggle the preference in their profile/settings page
- [ ] When enabled, the selected dyslexic-friendly font (e.g. OpenDyslexic or Atkinson Hyperlegible) is applied via a CSS class on the `<html>` or `<body>` element
- [ ] Font is served from static assets (not an external CDN) for privacy and reliability
- [ ] Preference persists across sessions (stored server-side)
- [ ] **No audit log** for this write (follows the `save_graph_layout()` pattern: it is UI preference state, not a business action). The service function docstring must note this explicitly.
- [ ] `track_activity()` is called (instead of `log_event()`) so the user's `last_activity_at` is still updated
- [ ] API endpoint exposes the preference for programmatic access

**Effort:** M
**Value:** Medium

---

## Passkey Authentication & Tenant Auth Policy

**User Story:**
As a super admin,
I want to require strong authentication (TOTP or passkey) for my tenant's users,
So that accounts are protected beyond email-based verification.

As a user,
I want to sign in with a passkey (biometric prompt) instead of typing passwords and codes,
So that authentication is faster and phishing-resistant.

**Context:**

WeftID currently supports password + email OTP as the baseline, with optional TOTP upgrade.
There is no tenant-level control over which authentication methods are required. The
`require_platform_mfa` flag on SAML IdPs exists in the schema and admin UI but is not
enforced in the SSO flow (bug). This feature introduces passkeys (WebAuthn/FIDO2) as a
passwordless primary auth method and gives super admins control over minimum auth strength.

**Tenant Auth Policy Model:**

Super admins configure the minimum authentication strength for their tenant:

* **Baseline** (default): Password + email OTP. Current behavior, no change.
* **Enhanced**: Super admin declares email OTP insufficient. Users must set up TOTP
  and/or passkey (admin controls which methods are allowed):
  * TOTP and passkey (user chooses one or both)
  * TOTP only
  * Passkey only

**Passkey Login Flow:**

1. User visits login page
2. Clicks "Sign in with passkey"
3. Browser/OS prompts biometric (Face ID, fingerprint, Windows Hello)
4. On success: fully authenticated. No password, no email code, no MFA step
5. Proceeds to dashboard (or SSO consent if SP-initiated)

**Passkey Registration:**

* Users register passkeys in account settings (opt-in regardless of tenant policy)
* Multiple passkeys supported (each named by the user, e.g. "MacBook", "iPhone")
* Registration generates backup codes (same pattern as TOTP)
* WebAuthn discoverable credentials (resident keys) with user verification required

**Coexistence (TOTP + Passkey):**

A user can have both TOTP and passkey registered. Login defaults to passkey when
available. A "Can't use passkey? Use one-time code" link falls back to password +
TOTP/email flow.

**Enforcement Flow (Enhanced Policy):**

When super admin enables enhanced auth and a user has not yet set up a qualifying method:

1. User signs in with email two-step (baseline) as normal
2. After successful baseline auth, redirected to setup page
3. User must register a passkey or set up TOTP (depending on allowed methods)
4. Cannot access dashboard, cannot complete SP-initiated IdP SSO until setup is done
5. Follows the same redirect-and-block pattern as forced password reset

**Recovery:**

* Backup codes: generated at passkey registration (like TOTP). Can be used when passkey
  device is unavailable.
* Admin recovery: admin can reset a user back to baseline auth (email OTP), clearing
  their enhanced auth requirement. User would need to set up again if tenant policy
  still requires enhanced auth.

**Platform MFA for IdP-Authenticated Users:**

The existing `require_platform_mfa` flag on SAML identity providers must be enforced.
When enabled, after successful SAML authentication, the user must complete their
configured two-step verification method before proceeding:

* If user has passkey: passkey prompt
* If user has TOTP: TOTP code entry
* Baseline: email OTP

**Admin Management:**

* Tenant security settings page: auth policy configuration (baseline/enhanced, allowed methods)
* User detail view: shows registered passkeys (name, created date, last used)
* Admin can revoke individual passkeys
* Admin can reset user to baseline auth
* User list: filterable by auth method (email, TOTP, passkey)

**Acceptance Criteria:**

*Tenant auth policy:*
- [ ] New tenant security setting: `required_auth_strength` (`baseline` | `enhanced`)
- [ ] New tenant security setting: `allowed_enhanced_methods` (controls which methods are available when enhanced)
- [ ] Super admin UI to configure auth policy on tenant security settings page
- [ ] Default: baseline (no change to existing behavior)
- [ ] API endpoints for reading/updating tenant auth policy

*Passkey registration:*
- [ ] `webauthn_credentials` table (user_id, tenant_id, credential_id, public_key, sign_count, name, created_at, last_used_at, etc.)
- [ ] Migration for new tables and tenant settings columns
- [ ] Account settings page: register new passkey (WebAuthn registration ceremony)
- [ ] Support multiple passkeys per user, each with a user-provided name
- [ ] Backup codes generated at passkey registration (same pattern as TOTP)
- [ ] Account settings: list registered passkeys with name, created date, last used
- [ ] Account settings: delete individual passkeys
- [ ] API endpoints for passkey registration, listing, and deletion

*Passkey authentication:*
- [ ] Login page: "Sign in with passkey" option (WebAuthn authentication ceremony)
- [ ] Successful passkey auth: fully authenticated, skip password and MFA
- [ ] Passkey bound to tenant subdomain (RP ID = tenant domain for isolation)
- [ ] User verification required (biometric/PIN, not just presence)
- [ ] Sign count tracked and validated to detect cloned credentials
- [ ] `user_signed_in` event logged with `method: "passkey"` in metadata

*Coexistence and fallback:*
- [ ] Users with both TOTP and passkey: login defaults to passkey
- [ ] "Can't use passkey? Use one-time code" falls back to password + TOTP/email flow
- [ ] Backup codes usable as fallback for passkey-only users

*Enforcement:*
- [ ] When enhanced auth required and user lacks qualifying method: redirect to setup after baseline login
- [ ] Setup page presents allowed methods (TOTP, passkey, or both)
- [ ] User cannot access dashboard until setup is complete
- [ ] User cannot complete SP-initiated SSO consent until setup is complete
- [ ] Follows forced-password-reset redirect-and-block pattern

*Recovery:*
- [ ] Admin can reset user to baseline auth (clears enhanced auth setup)
- [ ] Reset logs `user_auth_reset_to_baseline` event
- [ ] User re-enters enforcement flow on next login if tenant still requires enhanced

*Platform MFA enforcement (bug fix):*
- [ ] Enforce `require_platform_mfa` flag on SAML IdPs in the SSO flow
- [ ] After SAML auth, if flag set, require user's configured two-step method
- [ ] Supports passkey, TOTP, and email OTP based on user's method

*Admin tooling:*
- [ ] Tenant security settings: auth policy UI (baseline/enhanced, method selection)
- [ ] User detail: registered passkeys section (name, dates, revoke action)
- [ ] User list: filter by auth method
- [ ] Admin action: reset user to baseline auth

*Audit:*
- [ ] `passkey_registered`, `passkey_deleted`, `passkey_auth_success`, `passkey_auth_failure` event types
- [ ] `tenant_auth_policy_updated` event type
- [ ] `user_auth_reset_to_baseline` event type
- [ ] `platform_mfa_enforced` event type (for IdP users)
- [ ] `track_activity()` for read operations

**Effort:** XL
**Value:** High
**Version impact:** Minor (new feature, new tables, additive settings with defaults. Platform MFA enforcement is a bug fix bundled in.)

---

## HMAC-Based Export Data Verification

**User Story:**
As an admin sharing an audit export with a compliance auditor,
I want to prove that the data was generated by WeftID and has not been tampered with,
So that the auditor can trust the export as authentic evidence.

**Context:**

The verification target is the data content, not the XLSX file bytes. Excel files
change when opened, re-saved, or reformatted (column widths, fonts, etc.), so
HMACing the file itself would produce false negatives. Instead, HMAC the raw row
data in a canonical form before it enters openpyxl.

At verification time, the admin provides the file password and the XLSX. WeftID
extracts the cell values, serializes them in the same canonical form, and compares
the HMAC. This is format-independent: the data could even have been copied into
another spreadsheet and verification would still work.

The canonical form must be deterministic: fixed column order, consistent date
formatting, stable JSON key ordering for metadata, and a defined null representation.

**Acceptance Criteria:**

- [ ] Before building the workbook, serialize all export rows into a canonical form (e.g. newline-delimited JSON with sorted keys, fixed column order, ISO timestamps)
- [ ] Compute HMAC-SHA256 of the canonical bytes using a tenant-scoped HKDF-derived key
- [ ] Store the HMAC in the `export_files` record (new column, database migration)
- [ ] Add verification endpoint: `POST /api/v1/exports/{export_id}/verify` accepts file upload + password, decrypts, extracts cell values, re-serializes to canonical form, compares HMAC
- [ ] Admin UI: verification option on the background jobs page (upload file to check)
- [ ] Response clearly states "Data is authentic, generated by WeftID on [date]" or "Data does not match the original export"

**Effort:** S
**Value:** Low
**Version impact:** Patch (new endpoint, no breaking changes)

---

## Enforce Clean Unit/Integration Test Boundary

**User Story:**
As a developer,
I want tests to either fully mock the database or fully use it,
So that unit tests never leak queries to PostgreSQL, producing noisy error logs and hiding incomplete mocking.

**Problem:**
`tests/services/` and `tests/routers/` mix unit and integration patterns. Tests mock specific DB calls they care about but let side-effects (`track_activity`, `log_event`, `is_verbose_logging_active`) leak to the real database. This produced ~115 PG error log entries per test run. Temporary guards in conftest files reduce this to ~6, but the root cause is architectural.

**Acceptance Criteria:**
- [ ] Service and router conftest auto-mocks the database connection pool by default (nothing reaches PG)
- [ ] Tests that need real DB access opt in with `@pytest.mark.integration` (restores real pool)
- [ ] `tests/database/` remains unchanged (all integration by default, no marker needed)
- [ ] `tests/utils/` and `tests/jobs/` remain unchanged (already clean unit tests)
- [ ] Remove the UUID-validation guard fixtures from `tests/services/conftest.py` and `tests/routers/conftest.py` (no longer needed)
- [ ] Zero PG error log entries from unit tests (only expected constraint errors from database integration tests)
- [ ] All existing tests pass without modification (integration tests get the marker, unit tests work as-is)

**Effort:** M
**Value:** Medium (developer experience, test reliability, CI log clarity)
**Version impact:** None (test infrastructure only)

---

## Google Workspace Directory Sync

**User Story:**
As a tenant admin whose company uses Google Workspace,
I want WeftID to sync users and groups from my Workspace customer domain,
So that my directory reflection works the same way it does for Okta and Entra customers, even though Google does not push SCIM.

**Context:**

Google Workspace does **not** implement SCIM 2.0. Directory provisioning uses the Google Admin SDK Directory API instead. This is a separate connector from inbound SCIM, not a variant of it.

The destination data model and conflict semantics are identical to inbound SCIM (creates `group_type='idp'` groups, soft-deletes on removal, Google-wins-always), so most of the merge/lifecycle code is shared.

Pull-based rather than push-based, because Workspace does not push directory events. Implemented as a scheduled job in `app/jobs/`.

**Design Notes:**

- Auth: OAuth2 service account with domain-wide delegation, or admin-consented OAuth2 app. Service account is the standard pattern for non-interactive directory sync.
- Sync surface: users (active, suspended, deleted) and groups (with members) from a Workspace customer domain.
- Pull cadence: scheduled job, configurable interval per tenant (default e.g. 15 minutes), plus an on-demand "sync now" admin action.
- Incremental sync where Google's API supports it (`syncToken` / change-list APIs), full sync otherwise. Full sync as a fallback when sync state is lost or first run.
- Reuses the inbound-SCIM merge/conflict/soft-delete code paths (idempotent merge on Google's `id` or canonical email; soft-delete on removal; Google-wins-always for attribute conflicts).
- Connector identity stored alongside other IdP connections so the admin UI is unified.

**Acceptance Criteria:**

- [ ] Migration adds `google_workspace_connections` table (tenant-scoped, holds service account credentials encrypted, customer domain, sync state, sync interval)
- [ ] Admin UI: connect Google Workspace (upload/paste service account key, specify customer domain, configure sync interval)
- [ ] Admin UI: "sync now" button, last sync time, last sync status, error surface
- [ ] Scheduled job in `app/jobs/` runs at the configured interval per connection
- [ ] On-demand sync enqueues a one-off job
- [ ] Incremental sync uses Google's change-list API where available; falls back to full sync
- [ ] Users created via Google sync are merged with any pre-existing JIT user on `externalId` (Google `id`) or canonical email match
- [ ] Removed users are soft-deleted (deactivated), preserving MFA enrollment and audit history
- [ ] Groups synced from Google use `group_type='idp'` (read-only in WeftID)
- [ ] **Google-wins-always** for attribute conflicts
- [ ] Service account key is encrypted at rest using existing HKDF-derived key infrastructure
- [ ] Audit events: `google_workspace_connection_created`, `google_workspace_connection_updated`, `google_workspace_connection_deleted`, `google_workspace_sync_started`, `google_workspace_sync_completed`, `google_workspace_sync_failed`, `google_workspace_user_synced`, `google_workspace_user_deactivated`, `google_workspace_group_synced`
- [ ] Documentation page in `docs/admin-guide/` covering Google Workspace setup (service account creation in Google Cloud, domain-wide delegation, scope grants, connection in WeftID)
- [ ] Test coverage with mocked Google Admin SDK responses (no live API calls in tests)

**Effort:** M
**Value:** High (Google Workspace is the third major enterprise IdP; without it, the reflection-directory story has a gap that prospects will probe)
**Version impact:** Minor (new connector, new table, new job, new scopes; no breaking changes)

**Dependencies:**
- Reuses the merge/soft-delete/conflict-resolution plumbing from **Inbound SCIM**. Whichever of the two ships second is cheaper. Recommended order: Inbound SCIM first (it establishes the reflection-directory data flow and is more familiar territory), then Google Workspace as the second connector.
- Independent of **Outbound SCIM**, but most valuable when combined with it (sync in from Google → push out to downstream apps).

---

## Outbound SCIM: Additional Vendor Quirks and Connector Types

**User Story:**
As a tenant admin,
I want WeftID's outbound SCIM to support more downstream applications out of the box,
So that I can connect WeftID to the SaaS my organization uses without falling back to the spec-correct generic profile (which may not work for vendors that diverge from SCIM 2.0).

**Context:**

The initial Outbound SCIM release shipped with quirk modules for **Slack, GitHub, Atlassian, and GitLab**, plus a spec-correct generic profile. Real-world SaaS diverges from SCIM 2.0 in vendor-specific ways, so each new high-profile vendor benefits from a small quirk module that adjusts payload shape, PATCH semantics, error interpretation, or authentication.

Two related extensions also belong here: connector types that don't fit the "generic SCIM 2.0 client with quirks" mold (1Password Business uses a self-hosted bridge; Box wraps SCIM in OAuth2 client-credentials auth).

**Design Notes:**

- Each new vendor is a small file under `app/services/scim/quirks/<vendor>.py` plus recorded fixtures under `tests/fixtures/scim/<vendor>/`. The vendor's name extends the `service_providers.scim_kind` CHECK constraint and appears in the SP detail page's "Application type" dropdown.
- Alternate connector types (bridge model, alternate auth) are larger work: a new transport layer alongside the generic HTTP-bearer client. Likely a `scim_transport VARCHAR(50)` column or a separate `sp_scim_connector_kind` table, with `http_bearer` as the default.
- Priority within this backlog item should be driven by customer demand. The list below is "next-most-likely-to-be-asked-for," not a commitment to ship all of them.

**Candidate vendor quirks (incremental, ship as customer demand surfaces):**

- **Zoom**: `userName` must be the email address, even when `emails[]` carries it separately
- **Notion**: PUT-only for users (no PATCH); architecturally distinct enough that the quirk module needs to translate PATCH ops into full-resource PUTs
- **Linear**: custom role attributes via schema extension
- **PagerDuty**: split between team membership and schedule membership (both modelled as "groups" in WeftID; quirk decides which)
- **Datadog**: tenant-specific URL pattern (region in the base URL)
- **Vercel**: project-membership model differs from flat groups
- **Figma**: distinguishes editor vs viewer seats in non-standard ways
- **AWS IAM Identity Center**: email as the immutable identifier; strict
- **Snowflake**: custom role mapping via attribute extensions
- **CircleCI**: org structure differs from spec's flat groups
- **HashiCorp Cloud Platform**: mostly compliant; minor differences
- **Sentry**: SCIM on Business+; mostly compliant
- **Cloudflare Zero Trust**: mostly compliant

**Candidate alternate connector types (each is a larger, distinct piece of work):**

- **1Password Business** -- self-hosted SCIM bridge. Admins deploy a 1Password-provided bridge container in their own infra; WeftID pushes to the bridge, not directly to 1Password's cloud. Requires a new connector kind and likely a different config UX (bridge URL + bridge auth, not 1Password cloud credentials).
- **Box** -- OAuth2 client-credentials in front of SCIM. Bearer token is short-lived and refreshed; WeftID needs a token-management layer (acquire, cache, refresh) rather than the static-bearer model used by everyone else.

**Acceptance Criteria (per increment -- each vendor or connector type is its own sub-deliverable):**

- [ ] Per vendor quirk: new `app/services/scim/quirks/<vendor>.py` module with the appropriate transforms and error interpretation
- [ ] Per vendor quirk: recorded request/response fixtures in `tests/fixtures/scim/<vendor>/`
- [ ] Per vendor quirk: `scim_kind` CHECK constraint extended via migration; dropdown updated
- [ ] Per vendor quirk: documentation walkthrough added under `docs/admin-guide/` with screenshots of the vendor's bearer-token acquisition flow
- [ ] Per alternate connector type: new transport layer in `app/services/scim/transports/` with its own auth model
- [ ] Per alternate connector type: UI accommodates the new config shape (bridge URL, OAuth2 client ID/secret, etc.)
- [ ] Per alternate connector type: integration tests against a recorded or sandbox instance

**Effort:** Variable. Single vendor quirk = XS (one file + fixtures + docs page). Alternate connector type = M (new transport + UI + auth refresh logic).
**Value:** Per-vendor: scales with how many prospects ask for that vendor. Bridge/OAuth2 connectors: unlock specific high-value prospects who use those products.
**Version impact:** Each vendor quirk is a patch release (additive). Each alternate connector type is a minor release (new auth surface, new config columns).

**Dependencies:** Requires **Outbound SCIM (WeftID → Downstream Service Providers)** to be shipped first. This backlog item is the follow-on wave.

---

## Forward-Auth Proxy for HTTP Apps

**User Story:**
As a self-hoster running HTTP apps that have no built-in SSO (Sonarr, Radarr, Jellyfin admin, Grafana, internal dashboards, private wikis),
I want WeftID to act as a forward-auth provider so my reverse proxy can gate those apps behind WeftID sign-in,
So that I get SSO in front of legacy apps without modifying them.

**Context:**

Forward-auth (also called "auth_request" in nginx and "forward_auth" in Caddy) is the standard mechanism for putting SSO in front of HTTP apps that have no built-in authentication. The reverse proxy makes a subrequest to a dedicated check endpoint for every protected request; the auth server replies allow / deny / redirect-to-login.

This is the dominant pattern for protecting homelab and small-team apps (Sonarr / Radarr / Jellyfin admin pages, Grafana, internal dashboards, private wikis) that ship without SSO support. WeftID's stack (FastAPI + Postgres + worker) is light enough that an in-process forward-auth endpoint serves the job without a separate component to deploy, version, or scale.

**Design Notes:**

- New endpoint family: `GET /forward-auth/check` (and a paired `/forward-auth/start` for the OAuth-style redirect handshake). The reverse proxy calls `/check` as a subrequest on every protected request.
- Reverse-proxy contract: 200 on allow (with `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups`, and `X-Forwarded-Display-Name` headers for the upstream app to consume); 302 on missing/expired session (to `/forward-auth/start?return_url=<original>`); 403 on signed-in-but-denied.
- Cookie scope: WeftID's session cookie is already tenant-subdomain scoped. Forward-auth check inspects the same cookie. Apps live on the same parent domain (e.g. `grafana.id.example.com`) and share the cookie scope.
- New resource: **Proxy App**. Analogous to a SAML SP. Has: name, external URL pattern (`https://grafana.example.com`), group grants (which groups can access), optional forwarded-header config (which headers to set), optional public-paths list (URLs that bypass auth, e.g. `/healthz`). Lives in the admin UI alongside SAML SPs.
- Group-based access: reuses the existing SP-group-grant model. Effective vs direct membership configurable per app.
- Audit: each `/check` decision logs an audit event (configurable verbosity since per-request logging at scale would flood the log). Default: log on first allow per session, on every deny, and on session expiry.
- Reverse-proxy examples for the documentation: Traefik `forwardAuth` middleware, nginx `auth_request`, Caddy `forward_auth` directive. The docs page should show full working configs for each.
- One Postgres table: `proxy_apps` (tenant-scoped, name, URL pattern, header config, public paths). Group grants reuse the existing `sp_groups` table or a parallel `proxy_app_groups` table (decide during design; reusing is cleaner if a "ProtectedApp" parent abstraction emerges).
- Deployment: single container, no new component. The `/forward-auth/*` endpoints live in the existing FastAPI app, scaled by the same compose service.

**Acceptance Criteria:**

- [ ] Migration adds `proxy_apps` table (tenant-scoped, name, external URL pattern, public paths, forwarded-header config, available_to_all flag)
- [ ] Migration adds `proxy_app_groups` table for group-based access grants (or extends the existing SP-group plumbing if the data model converges)
- [ ] `GET /forward-auth/check` endpoint: 200 on allow with forwarded-user headers; 302 on missing/expired session; 403 on signed-in-but-denied
- [ ] `GET /forward-auth/start?return_url=...` endpoint: validates return_url against registered proxy apps for the tenant (prevents open-redirect); kicks off the standard sign-in flow; returns to the original URL on success
- [ ] Admin UI: **Proxy Apps** section under Service Providers (or its own top-level admin section, TBD during design) with create / edit / delete, group grants, public-paths list, forwarded-header config, copy-paste reverse-proxy config snippet
- [ ] Header forwarding: `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups`, `X-Forwarded-Display-Name` set on allow responses (configurable per app)
- [ ] Public-paths bypass: requests matching configured patterns return 200 without auth (for healthchecks, public assets)
- [ ] Audit events: `proxy_app_created`, `proxy_app_updated`, `proxy_app_deleted`, `proxy_app_grant_added`, `proxy_app_grant_removed`, `proxy_access_granted` (rate-limited: first allow per session), `proxy_access_denied`, `proxy_session_expired`
- [ ] My Apps dashboard surfaces proxy apps alongside SAML apps so users have a single launch point
- [ ] Documentation page in `docs/admin-guide/service-providers/forward-auth.md` with full working reverse-proxy configs for Traefik, nginx, and Caddy; explanation of cookie scope and subdomain requirements; troubleshooting (cookie not sent, headers not forwarded, infinite redirect loop)
- [ ] Test coverage: unit tests for the `/check` endpoint covering allow / deny / unauthenticated / public-path bypass / open-redirect rejection; integration test with a real Traefik container forwarding to a dummy upstream
- [ ] Rate limiting on `/check` (because the reverse proxy hits it on every request to every protected resource — needs to be fast and resilient to floods)

**Effort:** L
**Value:** Very High (the dominant pattern for protecting legacy HTTP apps in homelab and small-team deployments; one of the few SSO capabilities a tenant cannot get via SAML or OIDC alone)
**Version impact:** Minor (additive: new tables, new endpoints, new admin section, new event types; no breaking changes to SAML / OAuth2 / SCIM)

**Dependencies:**
- None hard. Builds on existing session middleware, group-based access plumbing, and the My Apps dashboard.
- Synergy with **Standard user attributes** (already shipped): the `X-Forwarded-*` headers can include any tenant-configured attribute, not just the four defaults.

---

## OIDC Upstream IdP Support (with Entra, Google, GitHub, Okta Presets)

**User Story:**
As a tenant admin whose upstream identity provider speaks OIDC (Entra ID, Google Workspace, GitHub, Okta, Keycloak, Auth0, or a custom IdP),
I want to add it as an upstream IdP in WeftID using OIDC instead of SAML,
So that I can federate to providers that prefer OIDC, use simpler client-secret configuration instead of certificate exchange, and reduce setup friction for tenants migrating off platforms that ship OIDC-only.

**Context:**

WeftID currently accepts only SAML 2.0 as an upstream federation protocol. OIDC is the more modern and increasingly common federation standard, especially for newer SaaS platforms and developer-oriented IdPs.

The design choice is **one generic OIDC connector + thin vendor presets** rather than building each provider from scratch:
- A spec-correct OIDC connector handles most real-world providers (Keycloak, Auth0, custom IdPs) with no per-vendor code.
- Thin preset layers for Entra, Google, GitHub, and Okta cover the vendor-specific quirks (tenant-scoped authority URLs, hosted-domain restrictions, org/team claim handling) without forking the core connector.
- Adding a new vendor preset later is a small per-vendor effort, not a re-architecture.

This is a peer protocol to the existing SAML IdP support, not a replacement. Both protocols share the same downstream user/group plumbing (JIT provisioning, attribute mirroring, group sync, privileged domain routing).

**Design Notes:**

- Auth flow: OIDC **authorization code with PKCE** as the only supported flow. No implicit, no hybrid. PKCE is required (not optional) since WeftID is a confidential client running server-side and PKCE adds defense-in-depth at near-zero cost.
- IdP discovery: prefer the OIDC discovery endpoint (`/.well-known/openid-configuration`). Manual configuration of the four endpoints (authorization, token, userinfo, JWKS) is supported as a fallback for IdPs that don't publish discovery.
- Client registration: per IdP connection, admin pastes client ID + client secret (encrypted at rest with the existing HKDF infrastructure). Some preset providers (GitHub, public IdPs) accept a client created in their console; others (Entra, Okta) require an app registration with specific redirect URIs and scopes.
- Standard scopes requested: `openid profile email`. Additional scopes per preset (e.g. `read:org` for GitHub group/team claims, `Directory.Read.All` for Entra group claims where the admin wants that).
- Claim → user attribute mapping: per-IdP configuration mapping OIDC claims (`given_name`, `family_name`, `email`, `picture`, `phone_number`, custom claims) to WeftID's standard user attribute registry. Reuses the attribute mirroring infrastructure shipped in 1.6.0.
- Group claim handling: standardized per preset. Entra emits `groups` claim with GUIDs; Google has no built-in group claim (admin must opt in to a custom claim mapping or sync groups separately); GitHub uses `read:org` + `/user/orgs` and `/user/teams` API calls; Okta emits a configurable `groups` claim.
- JIT provisioning: identical UX to SAML JIT. First-time login from an OIDC IdP creates the user; subsequent logins refresh mirrored attributes.
- NameID equivalent: OIDC's `sub` claim is the stable subject identifier, persisted per (idp_id, sub) pair so users are correctly correlated across sessions even if their email changes.
- Privileged domain routing: integrates with the existing privileged-domains feature. A domain bound to an OIDC IdP routes the user to that IdP at sign-in (parallel to the SAML behavior).
- Per-IdP redirect URI: WeftID exposes `https://<tenant>.id.example.com/auth/oidc/<idp_slug>/callback`. The admin pastes this into the IdP's app registration.

**Acceptance Criteria:**

**Core OIDC connector:**

- [ ] Migration adds `oidc_idp_connections` table (tenant-scoped, name, issuer URL, discovery URL or manual endpoint set, client ID, encrypted client secret, scopes, claim mapping JSON, group claim source, enabled flag)
- [ ] Admin UI: parallel to SAML IdP setup — create connection, choose vendor preset (Generic / Entra / Google / GitHub / Okta), paste credentials, configure attribute mapping, test, enable
- [ ] OIDC discovery endpoint parsing (`/.well-known/openid-configuration`) populates authorization / token / userinfo / JWKS endpoints; manual override path for IdPs without discovery
- [ ] Authorization code with PKCE flow: code_verifier generated per request, stored in session, validated on callback; state parameter validated for CSRF
- [ ] ID token validation: signature against the IdP's JWKS, issuer match, audience match, `nonce` claim match, expiry within tolerance
- [ ] Standard `openid profile email` scopes always requested; per-preset additional scopes configurable
- [ ] Claim → standard user attribute mapping reuses the attribute mirroring infrastructure from 1.6.0
- [ ] Stable user correlation on `(idp_id, sub)` pair; email changes upstream do not create duplicate accounts
- [ ] JIT provisioning on first login (parallel to SAML JIT)
- [ ] Privileged domain routing supports OIDC IdPs as a binding target

**Vendor preset: Generic OIDC**

- [ ] Spec-correct OIDC 2.0 client; works against any IdP exposing `/.well-known/openid-configuration`
- [ ] Group claim source configurable: which claim name (`groups`, `roles`, custom), value shape (list of strings, list of objects)
- [ ] Documentation page covers Keycloak, Auth0, and "custom IdP" setup walkthroughs

**Vendor preset: Entra ID OIDC**

- [ ] Authority URL: `https://login.microsoftonline.com/<tenant_id>/v2.0` (admin enters tenant ID; WeftID composes the URL)
- [ ] Default scopes: `openid profile email User.Read`
- [ ] Group claim: requires `Directory.Read.All` scope and "groups claim" enabled in the Entra app registration; emits GUIDs that WeftID can map to local group names via Microsoft Graph (optional)
- [ ] Documentation walkthrough: Entra app registration, redirect URI configuration, secret generation, admin consent
- [ ] Quirk handling: Entra's `oid` claim used as `sub` for correlation (per Microsoft's guidance) when `sub` is per-app-anonymous

**Vendor preset: Google Workspace OIDC**

- [ ] Authority URL: `https://accounts.google.com`
- [ ] Default scopes: `openid profile email`
- [ ] Hosted-domain restriction: per-connection `hd` parameter on the authorization request enforces a Workspace customer domain (rejects personal Google accounts)
- [ ] Group claim: not native to Google OIDC; admin can opt in to a custom-claim mapping or use the (separate) Google Workspace Directory Sync to populate groups
- [ ] Documentation walkthrough: Google Cloud OAuth client setup, consent screen configuration, redirect URI registration, hosted-domain restriction

**Vendor preset: GitHub**

- [ ] Authority URL: `https://github.com` (uses OAuth 2.0 with OIDC-shaped userinfo via `/user`, `/user/emails`, `/user/orgs`, `/user/teams`)
- [ ] Default scopes: `read:user user:email read:org` (last one only when group/team mapping enabled)
- [ ] Group claim source: GitHub orgs and teams pulled via additional API calls after token exchange; mapped into WeftID groups via configurable rules (org → group, `org/team` → group)
- [ ] Allowed orgs filter: per-connection allow-list of GitHub org slugs; users not in any allowed org are denied
- [ ] Documentation walkthrough: GitHub OAuth app creation, scope grants, org-allow-list configuration

**Vendor preset: Okta OIDC**

- [ ] Authority URL: `https://<okta_subdomain>.okta.com` or custom domain (admin enters)
- [ ] Default scopes: `openid profile email groups`
- [ ] Group claim: Okta-native `groups` claim; emit configuration depends on Okta authorization server (admin must enable the groups claim in Okta)
- [ ] Documentation walkthrough: Okta app integration creation, redirect URI configuration, group claim setup

**Cross-cutting:**

- [ ] Audit events: `oidc_idp_connection_created`, `oidc_idp_connection_updated`, `oidc_idp_connection_deleted`, `oidc_login_started`, `oidc_login_completed`, `oidc_login_failed`, `oidc_user_jit_provisioned`
- [ ] Test coverage with mocked IdP responses (no live API calls); recorded fixtures per preset covering discovery, code exchange, ID token validation, userinfo, group claim shapes
- [ ] Documentation page `docs/admin-guide/identity-providers/oidc-setup.md` covering the generic connector; per-preset walkthroughs in subpages (`oidc-entra.md`, `oidc-google.md`, `oidc-github.md`, `oidc-okta.md`)
- [ ] Glossary entries: OIDC, OpenID Connect, PKCE (cross-link from existing OAuth2 entry), authorization code flow with PKCE, OIDC discovery, JWKS, ID token, userinfo endpoint
- [ ] Privileged-domain UI accepts OIDC IdPs as a binding target alongside SAML IdPs

**Effort:** XL (single largest backlog item; new protocol surface, five preset implementations, parallel admin UX to SAML)
**Value:** High (modernizes WeftID's federation surface; opens the door to tenants whose upstream IdP ships OIDC-only or whose admins prefer OIDC's simpler credential model over SAML's certificate exchange)
**Version impact:** Minor (additive: new tables, new endpoints, new admin section, new event types; no changes to SAML or existing flows)

**Dependencies:**
- Builds on **Standard user attributes** ✅ (shipped in 1.6.0): claim → attribute mapping reuses the attribute registry and mirroring infrastructure.
- Builds on **Privileged domains** ✅: OIDC IdPs slot into the same binding surface as SAML IdPs.
- Independent of **Inbound SCIM (Okta and Entra → WeftID)** and **Google Workspace Directory Sync** (inbound directions). These items cover different ways the same upstream provider can populate WeftID; admins pick whichever fits their stack.

**Suggested implementation order** (when this item is broken into iterations by `/lead`):
1. Generic OIDC connector (the foundation; all presets sit on this)
2. Entra ID preset (largest enterprise target)
3. Google Workspace preset (parallel to Entra)
4. GitHub preset (developer-tenant differentiator, requires the extra-API-call group source)
5. Okta preset (last because Okta tenants typically already work via SAML)

---
