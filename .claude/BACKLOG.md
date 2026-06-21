# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

# Recommended Path Forward: Becoming SaaS-Palatable

This is a standing roadmap, not a work item. It records the **recommended sequence** for evolving WeftID from "multi-tenant SAML + SCIM federation platform" into an authentication middleware a SaaS builder would actually adopt — including the specific, frequently-asked capabilities **"multiple SSO per customer"** and **"social sign-in."** It frames the OIDC and Embedder Enablement items below; individual items hold the detail.

**Target customer profiles (in increasing ambition):**
1. *"Give me multiple SSO."* A customer (SaaS or org) that needs to connect several upstream IdPs per Organization (e.g. Okta + Entra + a partner's SAML).
2. *"Give me social sign-in."* A product that wants Google/GitHub/Apple/Microsoft/etc. login for end users, not just enterprise federation.
3. *"Let me build my SaaS on you."* A SaaS company that wants WeftID to be its entire identity layer — provision Organizations via API, self-serve SSO/SCIM setup for their customers, webhooks, hosted login, entitlements.

**Guiding principle:** do not pursue profile 3 (the embedder go-to-market) until WeftID is an *exceptionally strong and versatile auth middleware* — i.e. the OIDC surface is complete and ideally OpenID-certified. Profiles 1 and 2 are largely delivered *along the way* by the OIDC work, and are worth surfacing as marketable capabilities before the full embedder story exists.

**Recommended phase order:**

- **Phase 0 — Forward-Auth Proxy (IN PROGRESS — do not disrupt).** Current branch work. Finish and ship as planned. Nothing in later phases should reprioritize or interrupt it. *(See "Forward-Auth Proxy for HTTP Apps" below.)*

- **Phase 1 — Functional OIDC (both directions).** The foundation everything else needs.
  - *Upstream* (WeftID consumes OIDC IdPs): **OIDC Upstream IdP Support**. This is what delivers **"multiple SSO"** beyond SAML and the enterprise half of **"social sign-in"** (Google/GitHub/Entra/Okta presets). Multiple SSO *per tenant* already works for SAML today (per-IdP entity IDs); this extends it to OIDC.
  - *Downstream* (WeftID is an OIDC provider): **OIDC Provider (Downstream IdP for Apps)**. This is what lets a SaaS app say "Sign in with WeftID."

- **Phase 2 — Social sign-in breadth + OIDC hardening.** Make the auth surface genuinely versatile and credible.
  - **Social Sign-In Providers (Consumer IdPs)** — extends the generic OIDC connector with consumer providers (Apple, Microsoft personal, Facebook, Discord, LinkedIn, etc.) so **"social sign-in"** is a complete, marketable capability, not just the enterprise presets.
  - **OIDC Hardening & Certification** — logout, introspection/revocation, device grant, dynamic registration, stronger client auth, and OpenID Foundation certification. This is the bar that makes WeftID "insanely strong," and the explicit gate before Phase 3.

- **Phase 3 — Embedder Enablement (the SaaS go-to-market).** Only after Phases 1–2. The **"Theme: Embedder Enablement"** section below (9 items; MVP = Organizations API, Webhooks, Self-Serve SSO Portal, Guest Invitations). This turns "strong auth middleware" into "build your SaaS on us."

**Capability → item map (for the two named asks):**
- **"Multiple SSO"**: SAML multi-IdP per Organization — *already shipped*. OIDC multi-IdP — *OIDC Upstream IdP Support*. Self-service setup by the customer's own admin — *Self-Service SSO/SCIM Admin Portal* (Phase 3).
- **"Social sign-in"**: enterprise-flavored (Google/GitHub) — *OIDC Upstream IdP Support*. Full consumer breadth (Apple/Microsoft/Facebook/etc.) — *Social Sign-In Providers*. As primary login for invited externals — *External/Guest Invitations + Passwordless* (Phase 3).

---

## Wire forward-auth nonce cleanup into the background-job registry

**As a** WeftID operator
**I want** abandoned forward-auth handshake nonces purged on a schedule
**So that** the `forward_auth_nonces` table does not accumulate dead rows over time.

**Context:**

The forward-auth handshake records a single-use nonce at `/authorize` and consumes
it at `/callback`. A handshake the user abandons (closes the tab before `/callback`)
leaves an unconsumed, soon-expired row behind. `database.forward_auth_nonces.delete_expired_nonces(UNSCOPED, now)`
already exists and is tested, but nothing calls it on a schedule. `consume_nonce`
now also refuses expired rows (defense-in-depth), so stale rows are inert, just not
reaped.

**Acceptance Criteria:**

- [ ] Register a recurring job in `app/jobs/registry.py` that calls `delete_expired_nonces(UNSCOPED, now())`
- [ ] Job runs in `system_context()` and is covered by a test
- [ ] Reasonable cadence (e.g. hourly) and idempotent

**Effort:** S
**Value:** Low (housekeeping; no correctness impact given the expiry-bounded consume)

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

## OIDC Provider (Downstream IdP for Apps)

**User Story:**
As a tenant admin onboarding a downstream application that authenticates via OpenID Connect,
I want WeftID to act as a spec-correct OIDC provider (discovery document, signed ID tokens, userinfo, JWKS),
So that I can add "Sign in with WeftID" to modern apps that expect OIDC, instead of being limited to SAML or to the current opaque-token OAuth2 that those apps can't consume.

**Context:**

This is the **downstream** counterpart to the **OIDC Upstream IdP Support** item above — the two are different directions and must not be conflated:
- *Upstream* (above): WeftID is the OIDC **client/relying party**, consuming an external IdP (Entra, Google, etc.) so users can log in to WeftID.
- *Downstream* (this item): WeftID is the OIDC **provider/IdP**, so downstream apps can log in *to WeftID* and receive identity claims.

WeftID already ships an OAuth2 authorization-code (+ PKCE) and client-credentials provider (`app/services/oauth2.py`, `app/routers/oauth2.py`, `app/database/oauth2/`, `app/schemas/oauth2.py`), but it issues only **opaque** access/refresh tokens. There is no OIDC discovery document, no signed ID token, no `/userinfo` endpoint, and no published JWKS. Modern apps that say "Sign in with OIDC" cannot integrate against the current surface — they expect a discoverable OP with verifiable ID tokens. This is the single most-expected missing capability on WeftID's downstream surface and the natural complement to the SAML IdP that already exists.

The design is **additive on top of the existing OAuth2 provider**, not a rewrite: OIDC is OAuth2 plus an ID token, a discovery/JWKS surface, standardized claims, and a userinfo endpoint. The existing authorization-code + PKCE flow, client registry, consent page, and token store are reused; OIDC layers identity semantics on top.

**Design Notes:**

- Layer on the shipped OAuth2 provider. When a client requests the `openid` scope, the token response additionally includes a signed `id_token`; without `openid` the endpoint behaves exactly as today (backward compatible).
- Signing: RS256 with an asymmetric keypair (the relying party verifies with the public key, so a symmetric HKDF secret is unsuitable for the ID-token signature itself). Provision a dedicated RSA (or EC) signing key with rotation support and a stable `kid`; private key encrypted at rest using the existing crypto infrastructure in `app/utils/crypto.py`. Decide per-tenant vs per-instance signing key during grooming — per-tenant isolates blast radius and matches the RLS model but multiplies key management; per-instance is simpler. Default recommendation: per-tenant issuer + per-tenant key, consistent with the multi-tenant isolation posture.
- Issuer: tenant-scoped (`https://<tenant>.id.example.com`) so discovery, `iss`, and JWKS are unambiguous per tenant.
- `sub`: the stable WeftID user id (never the email), so relying parties get a durable subject even if email changes — parallel to the upstream item's `(idp_id, sub)` correlation rule.
- Claims: standard set from `profile`/`email`/`groups` scopes — `sub`, `email`, `email_verified`, `name`, `given_name`, `family_name`, and `groups` sourced from the existing group system (respecting DAG/effective membership).
- Access control: an app's OIDC login must honor the **same group-based access control** used by SAML SPs and forward-auth proxy apps (the shared `sp_group_assignments` grant model). A user with no grant to the app is denied at the authorize step, not merely given a token with empty groups.
- Multi-tenant: discovery, JWKS, issuer, and all token issuance are RLS-scoped; one tenant's keys/clients never resolve under another tenant's host.
- API-first (project rule): client/OIDC configuration management exposed under `/api/v1/` alongside the existing OAuth2 client API.

**Acceptance Criteria:**

- [ ] `GET /.well-known/openid-configuration` (tenant-scoped) returns a spec-compliant discovery document: `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, supported scopes, response types, grant types, subject types, `id_token_signing_alg_values_supported` (RS256), and claims supported
- [ ] `GET /.well-known/jwks.json` (or discovery-advertised path) publishes the active public signing key(s) with stable `kid`; supports key rotation with overlap (old key served until tokens signed by it expire)
- [ ] Token endpoint issues a signed `id_token` (RS256) when the `openid` scope is requested; omitted otherwise (backward compatible with existing opaque-token clients)
- [ ] ID token contains: `iss` (tenant issuer), `sub` (stable WeftID user id), `aud` (client id), `exp`, `iat`, `auth_time`, `nonce` (echoed from the authorization request when supplied), and profile/email/group claims per requested scopes
- [ ] `nonce` parameter accepted on the authorization request and bound into the ID token; replay of an authorization code is rejected (reuse existing single-use code semantics)
- [ ] `GET /userinfo` (Bearer access token) returns claims consistent with the ID token and the granted scopes; rejects expired/revoked/invalid tokens
- [ ] Scopes `openid profile email groups` supported and gate which claims are released; group claims sourced from the group system honoring effective (DAG) membership
- [ ] OIDC login honors the existing app group-based access control (`sp_group_assignments` shared grant model); ungranted users are denied at authorize, not issued a token
- [ ] Signing key provisioned with private key encrypted at rest; rotation procedure documented; `kid` stable per key
- [ ] All discovery/JWKS/token/userinfo behavior is tenant-scoped under RLS; cross-tenant key/client/issuer leakage covered by tests
- [ ] Per-client toggle or scope-gating so a relying party explicitly opts into OIDC (vs plain OAuth2); existing clients unaffected until they request `openid`
- [ ] API surface under `/api/v1/` for managing OIDC-enabled clients, documenting all accepted fields (per API-first rule)
- [ ] Audit events: `oidc_id_token_issued`, `oidc_userinfo_accessed`, `oidc_signing_key_rotated` (and reuse existing OAuth2 token/authorization events where applicable)
- [ ] Documentation: `docs/admin-guide/identity-providers/oidc-provider-setup.md` (registering a downstream app, discovery URL, redirect URIs, scopes/claims, group claim behavior); glossary cross-links to the existing OAuth2/PKCE/OIDC entries
- [ ] Test coverage: discovery document shape, JWKS publication + rotation, ID token signature/claims validation with a real RP verification path, nonce binding, userinfo, scope-gated claim release, access-control denial, multi-tenant isolation

**Effort:** L (new discovery/JWKS/userinfo surface and ID-token signing on top of an existing OAuth2 provider; smaller than the XL upstream item because the OAuth2 flow, client registry, and token store already exist)
**Value:** High (closes the most-expected gap on WeftID's downstream surface; "Sign in with OIDC" is the default integration expectation for modern apps, and today only SAML or opaque OAuth2 are available)
**Version impact:** Minor (additive: new well-known/JWKS/userinfo endpoints, ID-token issuance gated on the `openid` scope, new signing-key storage and event types; no breaking change to SAML, existing OAuth2 clients, or forward-auth)

**Dependencies:**
- Builds on the shipped **OAuth2 provider** (authorization code + PKCE + client credentials): reuses the flow, client registry, consent page, and token store.
- Builds on the **group system** and the shared **`sp_group_assignments` grant model** (also used by SAML SPs and the forward-auth proxy): OIDC apps slot into the same group-based access control.
- Peer to **SAML IdP** (downstream): both let a downstream app authenticate users against WeftID; admins pick the protocol the app speaks.
- Distinct from **OIDC Upstream IdP Support** (above): opposite direction; they share terminology but no code path.

**Suggested implementation order** (when broken into iterations by `/lead`):
1. Signing key model + rotation + JWKS endpoint (the trust anchor everything else verifies against)
2. ID token issuance gated on the `openid` scope (extends the existing token endpoint)
3. Discovery document + userinfo endpoint (the discoverable OP surface)
4. Scope-gated claims + group claim sourcing + app access-control enforcement
5. API management surface + docs + multi-tenant isolation tests

---

## OIDC Hardening & Certification

**User Story:**
As the WeftID product owner positioning WeftID as a best-in-class authentication middleware,
I want WeftID's OIDC surface to go beyond functional and reach spec-completeness with external certification,
So that integrators can trust WeftID's OIDC as "insanely strong and versatile" rather than self-asserted, and so the protocol surface is genuinely on par with WorkOS / Auth0 / authentik before any embedder go-to-market.

**Context:**

The **OIDC Provider (Downstream)** and **OIDC Upstream IdP Support** items get WeftID to *functional* OIDC: discovery, ID tokens, userinfo, JWKS, authorization-code + PKCE, JIT, presets. That is table stakes. The gap between "has an OIDC endpoint" and "an OIDC implementation you'd bet a product on" is a set of protocol-completeness features plus an objective, externally-verifiable quality bar.

This item is deliberately kept **separate** from the two functional OIDC items so that the first usable OIDC version ships without waiting on the long tail — but the completeness bar is explicitly on record. Per the product-owner sequencing decision (2026-06), the **Embedder Enablement** theme is gated behind this OIDC work; this item defines what "OIDC complete" means.

**North-star bar:** **OpenID Foundation certification.** Certification is the one objective signal that WeftID's OIDC is correct rather than merely present, and running the OpenID conformance suite surfaces spec gaps that would otherwise ship silently. Several acceptance criteria below exist specifically to pass conformance profiles.

**Acceptance Criteria:**

**Downstream provider completeness:**
- [ ] OIDC logout: RP-initiated logout (`end_session_endpoint`), front-channel logout, and back-channel logout — the OIDC parallel to the existing SAML SLO; advertised in discovery
- [ ] Token introspection endpoint (RFC 7662) for resource servers
- [ ] Token revocation endpoint (RFC 7009)
- [ ] Device Authorization Grant (RFC 8628) for CLIs / TVs / input-constrained devices
- [ ] Dynamic Client Registration (RFC 7591) + management (RFC 7592), gated by policy/credential
- [ ] Stronger client authentication: `private_key_jwt` and (where feasible) mTLS client auth, in addition to client-secret
- [ ] Pairwise subject identifiers (`pairwise` `subject_type`) for cross-client privacy, in addition to `public`
- [ ] Pushed Authorization Requests (PAR, RFC 9126) and signed request objects for higher-assurance flows
- [ ] Consent/scope-grant persistence and management (remembered consent, revocable grants)

**Upstream consumer completeness:**
- [ ] Back-channel logout receiver: honor logout initiated by an upstream OIDC IdP and terminate the corresponding WeftID session(s)
- [ ] RP-initiated logout to the upstream IdP on WeftID logout where the IdP supports it

**Certification & conformance:**
- [ ] Pass the OpenID Foundation conformance suite for the targeted profiles (at minimum: Basic OP, Config OP; stretch: Form Post OP, and the relevant RP profiles for the upstream side)
- [ ] Pursue formal OpenID Foundation certification for WeftID as an OP (and, if scoped, as an RP)
- [ ] Document certified profiles and any intentional deviations

**Cross-cutting:**
- [ ] Discovery document advertises every newly supported endpoint/capability accurately
- [ ] Audit events for logout, introspection, revocation, device-grant issuance, and dynamic registration
- [ ] Each feature independently testable; conformance run wired into CI where practical
- [ ] Docs updated: logout integration, introspection/revocation for resource servers, device-grant flow, dynamic registration, client-auth options

**Effort:** XL (broad protocol surface plus a certification effort; naturally splits into several iterations by RFC/feature)
**Value:** High (this is what makes WeftID's auth middleware credible and versatile; explicit prerequisite for the embedder repositioning per the 2026-06 sequencing decision)
**Version impact:** Minor (additive endpoints, grant types, and discovery metadata; no breaking change to the functional OIDC surface)

**Dependencies:**
- Builds on **OIDC Provider (Downstream IdP for Apps)** (the functional OP) and **OIDC Upstream IdP Support** (the functional RP). Start only after those are usable.
- Gating prerequisite for the **Embedder Enablement** theme (per 2026-06 sequencing).

**Suggested implementation order** (when broken into iterations by `/lead`):
1. OIDC logout (RP-initiated + front/back-channel) — closes the most visible functional gap
2. Token introspection + revocation — needed by any resource-server integration
3. Conformance-suite pass for Basic + Config OP profiles (drives correctness fixes across the board)
4. Device grant + dynamic client registration
5. Stronger client auth (`private_key_jwt`/mTLS) + pairwise subjects + PAR
6. Formal OpenID certification + documentation of certified profiles

---

## Social Sign-In Providers (Consumer IdPs)

**User Story:**
As a product team using WeftID for authentication,
I want my end users to sign in with consumer identity providers (Apple, Microsoft personal accounts, Facebook, Discord, LinkedIn, and similar),
So that "social sign-in" is a complete, marketable capability and not just the enterprise-flavored Google/GitHub presets that ship with upstream OIDC.

**Context:**

The **OIDC Upstream IdP Support** item delivers a generic OIDC connector plus enterprise-leaning presets (Entra, Google Workspace, GitHub, Okta). That covers the *enterprise* half of "social sign-in," but not the consumer breadth product teams expect when they say "let users log in with Apple/Facebook/Microsoft." This item extends the same generic OIDC/OAuth connector with consumer providers, reusing the existing connector, claim-mapping, and JIT plumbing rather than building bespoke flows.

It sits in **Phase 2** of the Recommended Path Forward (social-sign-in breadth), alongside OIDC hardening, after functional OIDC lands.

**Design Notes:**

- Build on the generic OIDC connector from **OIDC Upstream IdP Support**; most providers are thin preset layers (authority URL, scopes, claim quirks).
- Providers that aren't spec-OIDC (e.g. Facebook's Graph-flavored OAuth2, Apple's `form_post` + client-secret-as-JWT) get small per-provider adapters, mirroring the SCIM "quirks" pattern.
- Consumer providers are **end-user login** sources; they coexist with enterprise SSO and with invited-guest passwordless (ties into the Embedder **External/Guest Invitations** item).
- Per-Organization opt-in: an admin enables which social providers are offered; nothing appears on the login screen unless enabled.
- Account linking: a user who first signs in socially and later via another method should correlate on verified email (documented policy; reuse the upstream `(idp_id, sub)` + email-merge rules).

**Acceptance Criteria:**

- [ ] Apple sign-in (handles `form_post` response mode and client-secret-as-JWT signing)
- [ ] Microsoft personal accounts (consumer, distinct from the Entra enterprise preset)
- [ ] Facebook login (Graph-flavored OAuth2 adapter)
- [ ] At least two more common consumer providers (e.g. Discord, LinkedIn) shipped via the preset mechanism
- [ ] Each provider is a thin preset/adapter over the generic OIDC connector; non-OIDC quirks isolated per provider
- [ ] Per-Organization opt-in: providers are off until an admin enables them; login screen reflects only enabled providers
- [ ] Claim → user attribute mapping reuses the existing attribute registry
- [ ] Account linking/correlation on verified email documented and tested
- [ ] JIT provisioning parity with the upstream OIDC flow
- [ ] Audit events for social login start/success/failure and JIT provisioning
- [ ] Docs: per-provider setup walkthroughs (app registration, redirect URIs, scopes)

**Effort:** L (mostly presets/adapters on top of the generic OIDC connector; a few providers need real per-provider handling)
**Value:** Medium (completes the "social sign-in" capability named in the Recommended Path Forward; broadens WeftID's appeal beyond enterprise federation)
**Version impact:** Minor (additive provider presets; no change to existing flows)

**Dependencies:**
- Builds on **OIDC Upstream IdP Support** (the generic connector + preset mechanism). Do not start before that connector exists.
- Composes with the Embedder **External/Guest Invitations + Passwordless** item (social as a primary login method for externals).

---

## Optional Adaptive Auth Policies

**User Story:**
As a tenant admin with elevated security requirements,
I want to optionally enable adaptive authentication protections (login throttling/IP reputation, GeoIP allow-deny, breached-password checks, CAPTCHA),
So that I can harden my tenant's login against credential-stuffing and risky sign-ins without those protections being forced on tenants that don't want them.

**Context:**

authentik exposes a rich policy engine (Reputation, GeoIP, HaveIBeenPwned/zxcvbn, CAPTCHA) that gates its login flows. WeftID's login flow is intentionally opinionated and hard-coded, which keeps the attack/complexity surface small. This item adds a *curated, optional* subset of those protections **without** turning WeftID into a general policy engine.

**Hard constraint (product owner):** every protection here is **strictly opt-in, off by default, and per-tenant configurable.** The default login flow must be byte-for-byte unchanged unless a tenant admin explicitly enables a given protection. No protection may run, add latency, call an external service, or alter login UX in the default (un-configured) state. This is the governing requirement, not a nice-to-have — acceptance criteria are framed around it.

**Design Notes:**

- Each protection is an independent, separately-toggled feature; enabling one does not enable any other.
- All settings are tenant-scoped (RLS), surfaced in a tenant security-settings area, and auditable (enabling/disabling is an event).
- External-dependency protections (HaveIBeenPwned, GeoIP database, CAPTCHA provider) only ever make network calls or load data when that specific protection is enabled; the default deployment makes zero such calls.
- Fail-open vs fail-closed behavior per protection is an explicit, documented choice (e.g. HIBP lookup failure should not lock out logins; GeoIP allow-list failure mode is admin-configurable).

**Acceptance Criteria:**

- [ ] **Default-off invariant:** with no configuration, the login flow, its latency, its UX, and its outbound network calls are identical to today; covered by a regression test asserting no policy code path executes when all protections are disabled
- [ ] **Login throttling / IP reputation (opt-in):** per-tenant toggle; tracks failed-login attempts per IP/username and applies back-off or temporary block above a configurable threshold; counters scoped per tenant
- [ ] **GeoIP allow-deny (opt-in):** per-tenant toggle; admin configures allowed/denied countries or ASNs; configurable fail-open/fail-closed when GeoIP lookup is unavailable; GeoIP data only loaded when enabled
- [ ] **Breached-password check (opt-in):** per-tenant toggle; HaveIBeenPwned k-anonymity range query at password-set/change time; never sends the full hash; lookup failure fails open (does not block the password change); only calls HIBP when enabled
- [ ] **CAPTCHA on login (opt-in):** per-tenant toggle; pluggable provider (reCAPTCHA / hCaptcha / Turnstile); challenge only rendered when enabled, optionally gated on prior failed attempts
- [ ] Each protection independently toggleable; enabling/disabling emits an audit event (`auth_policy_enabled` / `auth_policy_disabled` with which policy)
- [ ] All configuration tenant-scoped under RLS; one tenant's settings never affect another
- [ ] API-first: protections configurable via `/api/v1/` with documented fields
- [ ] Documentation: admin-guide page describing each protection, its default-off behavior, external dependencies, and fail-open/closed semantics

**Effort:** L (four independent protections, each with config, enforcement, audit, and external-dependency handling)
**Value:** Low (nice-to-have hardening; not urgent. Most valuable to security-conscious tenants, but must never become friction for the default install)
**Version impact:** Minor (additive: new per-tenant settings, new optional enforcement paths gated behind toggles, new event types; default behavior unchanged)

**Dependencies:**
- Independent of the OIDC items. Touches the login flow and tenant settings only.
- Each protection can ship independently; this item can be broken into one iteration per protection by `/lead`.

---

# Theme: Embedder Enablement (WeftID as Identity-as-a-Service for SaaS Builders)

**Strategic framing:**

The items in this theme reposition WeftID from a *federation tool an organization's IT runs* to an *embeddable identity layer a SaaS company builds on* — the WorkOS / Auth0-B2B / Frontegg / Stytch playbook. In this model the **SaaS company is the customer**, and each of *their* customers is a WeftID **Organization** (an existing tenant, RLS-isolated; "Organization" is the embedder-facing term, `tenant` remains the internal data-model term). The SaaS provider never builds SSO, SCIM, OIDC, MFA, or user management — they call WeftID's APIs and ship "enterprise-ready" from day one.

**Why this is the strongest use case:** the buyer of a SaaS product is not the IT department that owns Entra/Okta. Asking that IT department to stand up federation "just so external/partner users can get into an app" is exactly the work IT deflects. When the SaaS provider owns the identity layer via WeftID, the customer can onboard external users — *auditably* — without filing that ticket. WeftID already has the hard middleware (multi-tenant RLS isolation, SAML SP/IdP, inbound + outbound SCIM, groups, audit log, per-tenant branding, and the queued OIDC provider). What's missing is the **embedding control plane**: programmatic org lifecycle, a platform credential, event egress, self-service connection setup, and external-user onboarding.

**MVP of the theme:** items 1, 3, 4, 5 (provision orgs, sync via webhooks, self-serve SSO setup, invite auditable externals). Item 2 ships inside item 1. The rest compound value but are not load-bearing.

**Two ways to set a customer up.** Connection setup (IdPs, SCIM, groups, attributes) can happen either way, and both are always available with no mode flag — the SaaS picks per customer: *delegated* (hand the customer's IT admin a magic link to self-configure — the **Self-Service SSO/SCIM Admin Portal**) or *managed* (the SaaS provider's own staff do it on the customer's behalf via the **Operator Backoffice / master tenant**). The two items are deliberate mirror images.

**Sequencing (product owner, 2026-06):** this entire theme is **deferred behind the OIDC work.** WeftID must first be an exceptionally strong and versatile authentication middleware — both OIDC directions solid (the **OIDC Upstream IdP Support** and **OIDC Provider (Downstream IdP for Apps)** items, plus any OIDC-completeness follow-ups) — before the embedder go-to-market is pursued. Do not start Embedder Enablement items until the OIDC surface is complete. The dependency graph already reflects this: the hosted-login item builds on the OIDC provider, and the self-serve SSO portal leans on the upstream OIDC presets.

---

## [Embedder] Organizations / Tenant Lifecycle API

**User Story:**
As a SaaS engineering team embedding WeftID,
I want to create, configure, suspend, and delete customer Organizations programmatically via API,
So that a customer signing up in my product automatically gets an isolated WeftID Organization without anyone running a CLI command.

**Context:**

Today tenants are created **only** by the `python -m app.cli.provision_tenant` CLI script. That is a non-starter for embedding: an embedder needs to `POST /organizations` at customer-signup time, from their own backend, with no shell access to the WeftID host. This item exposes the full tenant lifecycle (which already exists internally) as a control-plane REST API. "Organization" is the embedder-facing name for what is internally a tenant (subdomain, RLS scope, branding).

**Design Notes:**

- The API is **control-plane** (cross-tenant): it creates and manages tenants, so it cannot be authenticated by a per-tenant credential. It depends on the **Platform API keys** item (#2) for auth.
- Reuse the existing provisioning logic in `app/cli/provision_tenant.py` / `app/services/` rather than forking it; the CLI becomes a thin wrapper over the same service path.
- Org creation provisions: subdomain (or auto-assigned), display name, initial branding, and optionally a first admin user (invitation email) — matching what the CLI does today.
- Lifecycle states: active, suspended (login disabled, data retained, billing/offboarding hold), deleted (hard delete with cascade, or soft-delete + purge window — decide during grooming).
- Idempotency keys on create (so a retried signup webhook doesn't double-provision).

**Acceptance Criteria:**

- [ ] `POST /api/v1/organizations` creates an Organization (subdomain optional/auto, name, branding, optional first-admin invite); idempotency-key supported
- [ ] `GET /api/v1/organizations` lists, `GET /api/v1/organizations/{id}` retrieves
- [ ] `PATCH /api/v1/organizations/{id}` updates name/branding/settings
- [ ] `POST /api/v1/organizations/{id}/suspend` and `/reactivate` toggle login without data loss
- [ ] `DELETE /api/v1/organizations/{id}` removes the Organization with documented cascade semantics
- [ ] All endpoints authenticated by a platform (control-plane) credential, never a per-tenant token
- [ ] The existing `provision_tenant` CLI is refactored to call the same service path (no logic divergence)
- [ ] Every lifecycle action emits an audit event attributable to the platform actor
- [ ] API docstrings document all accepted fields (API-first rule); endpoints documented in the self-hosting/embedder guide

**Effort:** L
**Value:** High (foundational — embedding is impossible without programmatic org provisioning)
**Version impact:** Minor (additive control-plane endpoints; CLI behavior preserved)

**Dependencies:**
- Requires **Platform API keys & scoped management auth** (#2) for authentication.
- Reuses existing tenant provisioning service logic.

---

## [Embedder] Platform API Keys & Scoped Management Auth

**User Story:**
As a SaaS platform operator,
I want a privileged platform API credential (distinct from per-tenant tokens) that can manage all of my Organizations,
So that my backend can drive org lifecycle, connection setup, and cross-org reporting through one auditable, scope-limited control-plane identity.

**Context:**

All current API auth is **per-tenant** (session, per-tenant OAuth2 client, SCIM bearer). There is no credential that legitimately operates **above** a single tenant. The control-plane items in this theme (org lifecycle, admin portal links, webhooks config) require exactly that. This item introduces a platform-scoped credential with explicit, least-privilege scopes — not a god-mode key.

**Design Notes:**

- Platform keys live outside any single tenant's RLS scope; their use of `UNSCOPED` operations is deliberate and must be tightly bounded and audited (this is the one place cross-tenant access is legitimate, so it needs strong guardrails).
- Scopes (least privilege): e.g. `organizations:write`, `organizations:read`, `connections:write`, `webhooks:write`, `directory:read`. A key grants only the scopes it was issued with.
- Key rotation, revocation, and per-key audit (every control-plane action records which platform key performed it).
- Keys are hashed at rest (Argon2, same as OAuth2 tokens); shown once on creation.
- Management surface to create/rotate/revoke keys (super-admin/operator only), plus API.

**Acceptance Criteria:**

- [ ] Platform API key type with hashed-at-rest storage, shown once on issue
- [ ] Scope model enforced per request; a key lacking a scope is denied (403) with a clear error
- [ ] Cross-tenant (`UNSCOPED`) access is reachable **only** via platform keys and only for whitelisted control-plane operations; covered by tests asserting per-tenant tokens cannot reach control-plane endpoints
- [ ] Create / list / rotate / revoke keys via API and admin UI (operator role)
- [ ] Every control-plane action audits the acting platform key id
- [ ] Rate limiting on control-plane endpoints
- [ ] Docs: key issuance, scope reference, rotation, and the security model for cross-tenant access

**Effort:** M
**Value:** High (the auth foundation the entire control plane depends on)
**Version impact:** Minor (additive credential type + scope enforcement; existing per-tenant auth unchanged)

**Dependencies:**
- Prerequisite for items #1, #4, #3 (their endpoints are control-plane).
- Reuses existing crypto/hashing infrastructure.

---

## [Embedder] Outbound Webhooks / Event Streaming

**User Story:**
As a SaaS engineering team,
I want WeftID to push identity events to my backend via signed webhooks,
So that I can keep my own user/membership records in sync without polling WeftID's API.

**Context:**

WeftID has a rich internal audit/event log, but **it never leaves WeftID** — there are no outbound webhooks today. An embedder's app must learn, in near-real-time, when a user is provisioned via SCIM, deactivated, added to a group, or when an SSO connection goes live, so it can mirror that state into its own database. This is essential plumbing for embedding.

**Design Notes:**

- Reuse the outbound-SCIM worker patterns (`app/services/scim/worker.py`): a durable queue, retries with exponential backoff, dead-letter after N attempts, and a delivery log.
- Per-Organization webhook endpoints **and** platform-level endpoints (an embedder may want one firehose across all their orgs, or per-org routing — support both).
- HMAC-signed payloads (shared secret per endpoint) with a timestamp to prevent replay; documented verification recipe.
- Event catalog mapped from the existing `event_types` registry: e.g. `user.created`, `user.updated`, `user.deactivated`, `user.deleted`, `group.membership.changed`, `scim.user.provisioned`, `sso.connection.activated`, `mfa.enrolled`.
- At-least-once delivery; consumers must dedupe on event id (documented).

**Acceptance Criteria:**

- [ ] Configurable webhook endpoints (per-Organization and platform-wide) with subscribed event types
- [ ] HMAC signature header + timestamp; documented verification example
- [ ] Durable delivery with retry/backoff and dead-letter; delivery log queryable
- [ ] Event catalog mapped from `app/constants/event_types.py`; documented payload schemas
- [ ] At-least-once semantics with stable event ids for consumer dedupe
- [ ] Test/redeliver controls (send test event, replay a failed delivery)
- [ ] API + admin UI to manage endpoints; secrets shown once
- [ ] Docs: event catalog, signature verification, retry semantics

**Effort:** L
**Value:** High (without event egress, embedders must poll; this is core sync plumbing)
**Version impact:** Minor (additive: new tables, worker, endpoints, event delivery)

**Dependencies:**
- Reuses the outbound-SCIM worker/queue/retry patterns.
- Platform-level endpoints require **Platform API keys** (#2); per-org endpoints work with tenant auth.

---

## [Embedder] Self-Service SSO/SCIM Admin Portal (Magic-Link)

**User Story:**
As a SaaS provider onboarding an enterprise customer,
I want to send that customer's IT admin a branded, self-service link where they configure their own SSO and SCIM connection,
So that I never have to manually broker certificate/metadata exchange, and the customer's IT can do it themselves in minutes.

**Context:**

This is the theme's **killer differentiator** and the direct answer to the stated pain ("IT won't set up federation, and the SaaS buyer can't do it for them"). Modeled on WorkOS's Admin Portal: the embedder generates a short-lived, scoped link via API; the customer's IT admin opens it, picks their IdP (Entra/Okta/Google/generic SAML or OIDC), and is walked through metadata/cert exchange and SCIM token setup — all within their own Organization's RLS scope, with no access to anything else. It converts "stand up federation" from a multi-week support thread into the customer admin's own guided 10-minute task.

**Design Notes:**

- Embedder calls `POST /api/v1/organizations/{id}/portal-links` (control-plane) → returns a short-lived signed URL scoped to that Organization and a specific intent (`sso`, `scim`, or `both`).
- The portal is a **restricted, branded UI** that exposes *only* connection setup for that one Organization — not the full admin app. Reuses the existing SAML/OIDC IdP and inbound-SCIM configuration surfaces, wrapped in a guarded, single-purpose flow.
- Guided setup per IdP preset (reuse the upstream SAML presets and, once shipped, the OIDC upstream presets): copy-paste redirect URIs/ACS URLs/metadata, upload/import IdP metadata, generate SCIM bearer token.
- Link is single-Organization, expiring, optionally single-use; all actions inside it audit as the customer admin (or a portal-actor), not the platform.
- On completion, fire `sso.connection.activated` / `scim.connection.activated` webhooks (#3) so the embedder knows the customer is live.

**Acceptance Criteria:**

- [ ] `POST /api/v1/organizations/{id}/portal-links` issues a short-lived, signed, Organization-scoped portal URL with an intent (sso/scim/both)
- [ ] Portal UI exposes only connection setup for that Organization; cannot navigate to users, billing, or other orgs (enforced server-side, not just UI)
- [ ] Guided SSO setup (SAML now; OIDC upstream when that item ships) with preset walkthroughs and metadata/cert import
- [ ] Guided SCIM receiver setup (generate/show bearer token, endpoint URLs)
- [ ] Portal is brandable per embedder/Organization
- [ ] Links expire; actions inside audit to the customer admin/portal actor; completion fires connection-activated webhooks
- [ ] Abuse protections: link expiry, optional single-use, rate limiting
- [ ] Docs: embedder flow (generate link) + customer-admin flow (use link)

**Effort:** L
**Value:** High (the standout differentiator; directly removes the IT-federation bottleneck)
**Version impact:** Minor (additive: portal-link issuance, a guarded portal UI over existing config surfaces)

**Dependencies:**
- Requires **Platform API keys** (#2) to issue links; **Webhooks** (#3) for completion signals.
- Reuses existing SAML IdP + inbound-SCIM config; gains OIDC upstream presets when that item ships.

---

## [Embedder] Operator Backoffice: Manage Organizations On-Behalf (Master Tenant)

**User Story:**
As a SaaS provider running WeftID for my customers,
I want a designated **master Organization** whose authorized members can enter any other Organization and configure its upstream identity setup (IdPs, SCIM, groups, user attributes, branding, invitations) on the customer's behalf,
So that I can fully manage customers who want it done for them — auditably, through a backoffice and API — without sending a self-serve portal link and without shell/CLI access to the host.

**Context:**

This is the **inverse and complement** of the **Self-Service SSO/SCIM Admin Portal** (#4). That item is the *delegated* path: hand the customer's own IT admin a magic link and let them self-configure. This item is the *managed* / done-for-them path: the SaaS provider's own staff do the setup inside the customer's Organization. Per the product-owner decision (2026-06), **both paths are always available with no mode flag** — the SaaS picks per interaction whether to send a portal link or do it themselves.

**Core architectural concept (product-owner direction):** each deployment (the multi-tenant database) can designate one existing tenant as the **master tenant**. Members of the master tenant, subject to explicit operator scopes, can operate across **all** other tenants in that deployment. This is the *human-operator* embodiment of the control plane — the SaaS provider's own WeftID Organization elevated to operator status — as opposed to the *machine credential* in **Platform API keys** (#2). The two should resolve to one scope model with two principal types (human operator, platform key); grooming must unify them.

**Tenant-isolation-model note (architecturally significant):** today the only human principals are per-tenant admins (`super_admin` is scoped to a single tenant). This item introduces a sanctioned, bounded **cross-RLS operator path** for humans. Rationale: embedders managing customers directly have no cross-tenant human operator surface today; tenant config is reachable only from inside each tenant. The master-tenant path must be: explicitly designated (never implicit; default none), least-privilege scoped, and fully audited **in the target Organization's own trail** as an on-behalf action by the named master operator — so the customer's audit history stays honest.

**On-behalf model (per decision): scoped operations, no impersonation.** Operators never assume a customer user's identity or session. They perform operations that *target* a specific Organization (configure its IdP, SCIM connection, groups, attributes, etc.) carrying the master operator's own identity. Narrower blast radius than login-as impersonation, and every action is attributable to a real operator.

**Design Notes:**

- **Master-tenant designation:** a deployment-level setting marking one existing tenant as master/operator. Default: none (no cross-tenant operator surface exists unless explicitly designated). Designation is itself an audited, operator-only action.
- **Authorization:** cross-tenant operator powers gated by master-tenant membership **plus** explicit operator scopes (share the scope model with Platform API keys #2 — e.g. `organizations:read`, `connections:write`, `directory:write`). Distinct from in-tenant `super_admin`, which stays single-tenant.
- **Execution:** cross-tenant operations reuse the existing per-tenant service functions, invoked with a *target* `tenant_id` by an authorized master operator (the legitimate, bounded `UNSCOPED` → re-scope-to-target pattern). No existing per-tenant endpoint may be widened; ordinary tenant admins must still be unable to reach another tenant.
- **Operable surface (target Org):** upstream IdP setup (SAML now; OIDC upstream when shipped), inbound/outbound SCIM connection setup, groups, user attributes, branding, guest invitations, entitlements — the Organization admin configuration surface, reachable from the master side.
- **Backoffice UI (first-party operator console):** list all Organizations, drill into one, perform the above. The API underlies it and is non-negotiable (API-first); the UI is the turnkey path for SaaS ops/support staff who don't want to build their own tooling.
- **Audit & attribution:** every on-behalf action writes to the **target** Org's audit trail, distinctly flagged as performed on-behalf by `<master operator>`, **and** to the master tenant's own operator log (who entered which Org and what they changed). Both sides stay legible.
- **Open grooming questions:** per-Organization opt-out of on-behalf access (some embedders may contractually need to disable it for a given customer); whether to reconcile/rename the master-tenant operator role against `super_admin`.

**Acceptance Criteria:**

- [ ] A deployment can designate exactly one master tenant; default none; designation is audited and restricted to operator/super-admin
- [ ] Authorized master-tenant members can list every Organization and select one to operate within (read + configure), gated by explicit operator scopes
- [ ] On-behalf operations cover, for any target Organization: upstream IdP config (SAML; OIDC when shipped), SCIM connection setup, groups, user attributes, branding, guest invitations, entitlements
- [ ] **No impersonation:** operators never assume a customer user's identity/session; operations carry the master operator identity
- [ ] Every on-behalf action is audited in the **target** Organization's trail, distinctly flagged as on-behalf by `<master operator>`, and also recorded in the master tenant's operator log
- [ ] Cross-tenant (`UNSCOPED` → target) access is reachable **only** via master-tenant operators (or platform keys #2) and only for whitelisted configuration operations; tests assert ordinary per-tenant admins cannot reach another tenant
- [ ] First-party operator backoffice UI (list orgs, drill in, configure) over the same API; API docstrings document all accepted fields (API-first rule)
- [ ] Always-available alongside the Self-Service Portal (#4); **no managed/delegated mode flag** — the SaaS chooses per interaction
- [ ] Rate limiting on cross-tenant operations; missing-scope requests denied (403) with a clear error
- [ ] Docs: master-tenant designation, operator scope reference, on-behalf audit semantics, and the security model for the sanctioned cross-tenant path

**Effort:** L (introduces a cross-tenant operator authorization model + on-behalf audit attribution + a backoffice UI over existing config surfaces; may split into "auth model + audit" then "backoffice UI" iterations)
**Value:** High (the *done-for-them* half of the embedder management story; pairs with #4 to cover both "give customers control" and "do it for them")
**Version impact:** Minor (additive: master-tenant designation, cross-tenant operator scopes, backoffice, on-behalf audit attribution; no change to existing per-tenant flows). Architecturally significant despite being additive — it introduces the first sanctioned cross-RLS human-operator path, so the isolation-model rationale above must be honored during implementation.

**Dependencies:**
- Shares the scope model with **Platform API keys** (#2) — unify during grooming (one scope set, two principals: human operator and machine key).
- Complements **Self-Service SSO/SCIM Admin Portal** (#4): same target config surfaces, opposite actor (SaaS operator vs. customer admin).
- Operates over the org list/lifecycle from **Organizations / Tenant Lifecycle API** (#1).
- Gains OIDC-upstream config as a target surface when **OIDC Upstream IdP Support** ships.
- Sequenced within the Embedder theme (deferred behind the OIDC work per the 2026-06 decision).

---

## [Embedder] External / Guest User Invitations + Passwordless Login

**User Story:**
As an admin in a customer Organization (or a SaaS provider acting on their behalf),
I want to invite external/partner users who authenticate without going through our corporate IdP, using passwordless login,
So that contractors, partners, and cross-org collaborators get auditable access to the app even though they can't be added to our Entra/Okta tenant.

**Context:**

This is the second half of the stated pain: enterprises force their *own* staff through SSO, but the people who actually need app access are often **externals who cannot be provisioned into the corporate IdP at all.** Today WeftID has email OTP only as an **MFA factor**, not as a primary login method, and no first-class "invite an external" flow. This item makes passwordless (magic-link / email-OTP, optionally social) a **primary** authentication path and adds guest-user invitations that coexist with SSO users in the same Organization, under one audit trail.

**Design Notes:**

- Promote email-OTP/magic-link from MFA-only to a **primary** login method (per-Organization opt-in).
- Guest invitation flow: an admin (or the embedder via API) invites an external by email; the invite carries Organization + group/access assignment; the user accepts via magic link and never touches the corporate IdP.
- Guests are clearly distinguished from SSO/directory-sourced users (badge/flag), and are fully represented in the audit log, group system, and access checks.
- Optional social login for guests (reuses the upstream OIDC/social work — Google/GitHub) where the embedder enables it.
- Coexistence: an Organization can have SSO-required internal users and invited external guests simultaneously (ties into the per-org auth policy item #6).

**Acceptance Criteria:**

- [ ] Magic-link / email-OTP available as a **primary** login method (per-Organization opt-in), not just MFA
- [ ] Guest invitation via admin UI and API: invite by email with Organization + group/access assignment
- [ ] Guest accepts via magic link, bypassing any configured corporate IdP, and lands with the assigned access
- [ ] Guests flagged distinctly; appear in audit log, groups, and access checks like any user
- [ ] Optional social login for guests where enabled (reuses upstream OIDC/social)
- [ ] SSO users and guests coexist in one Organization without conflict
- [ ] Invitation lifecycle: pending/accepted/expired/revoked, with audit events
- [ ] API-first; documented fields

**Effort:** M
**Value:** High (directly solves the "auditable external access without corporate SSO" frustration that motivates the whole repositioning)
**Version impact:** Minor (additive: primary passwordless path, invitation flow, guest flag)

**Dependencies:**
- Complements **Per-organization auth policy** (#6) for SSO-required-vs-guest coexistence.
- Optional social login reuses the **OIDC Upstream IdP Support** work.

---

## [Embedder] Per-Organization Auth Policy (SSO-Required vs. Invited-External-Allowed)

**User Story:**
As an admin in a customer Organization,
I want to require SSO for users on our corporate domain while allowing invited externals to use passwordless,
So that employees are always forced through our IdP but partners and contractors can still get in.

**Context:**

Embedding customers need **mixed-mode** access: corporate identities must go through SSO (compliance), but invited externals must not be blocked by it. This item adds a per-Organization policy layer on top of the existing privileged-domain routing: domain-matched users are routed to (and required to use) the configured IdP, while invited guests use passwordless — all in one Organization, one audit trail.

**Design Notes:**

- Extends existing privileged/protected-domain routing: a verified corporate domain bound to an IdP can be marked **SSO-required** (password/passwordless disabled for matching emails).
- Guests (item #5) are exempt from the SSO-required rule by virtue of being invited externals.
- Per-Organization configuration; auditable when changed; sensible safe default (no enforcement unless configured).

**Acceptance Criteria:**

- [ ] Per-Organization policy: mark a domain (or the whole org) as SSO-required
- [ ] SSO-required users on a matching email domain cannot use password/passwordless; routed to the bound IdP
- [ ] Invited guests remain able to authenticate passwordlessly despite an SSO-required policy
- [ ] Policy changes are audited; default is non-enforcing
- [ ] Clear end-user messaging when a login method is blocked by policy
- [ ] API-first; documented

**Effort:** M
**Value:** Medium (high for compliance-sensitive customers; depends on #5 to be meaningful)
**Version impact:** Minor (additive policy layer on existing domain routing; no change to default behavior)

**Dependencies:**
- Builds on existing **privileged/protected domain** routing.
- Pairs with **External/Guest invitations** (#5).

---

## [Embedder] Hosted / Embeddable Login (AuthKit-Style) with White-Label on Customer Domains

**User Story:**
As a SaaS engineering team,
I want a turnkey, brandable hosted login I redirect users to (optionally on the customer's own domain),
So that I get SSO, MFA, and passwordless without building or maintaining any login UI myself.

**Context:**

Even with the OIDC provider shipped, embedders still benefit from a **turnkey login experience** they don't build — the WorkOS AuthKit model. The SaaS app redirects to WeftID's hosted login; WeftID handles IdP selection, SSO, MFA, and passwordless, then returns the user via the OIDC provider flow. White-labeling (per-Organization branding, optional custom/customer domain) makes the login feel native to the SaaS product.

**Design Notes:**

- Builds directly on the **OIDC Provider (Downstream)** item — the hosted login is the human-facing front end; OIDC is the protocol hand-off.
- Per-Organization branding already exists; extend to a fully white-labeled hosted login page.
- Optional custom-domain hosting reuses the protected-domains/portal-host + on-demand-TLS infrastructure from the forward-auth work.
- IdP discovery/selection: if the Organization has SSO configured, route appropriately; otherwise present passwordless/guest options (ties into #5/#6).

**Acceptance Criteria:**

- [ ] Hosted login screen, fully branded per Organization, driving SSO + MFA + passwordless
- [ ] Redirect-based hand-off to embedder via the OIDC provider flow (standard authorization-code + PKCE)
- [ ] IdP selection/routing based on Organization config and email domain
- [ ] Optional custom-domain hosting via the protected-domains/portal-host + on-demand-TLS infra
- [ ] No login UI required on the embedder side; documented integration (redirect, callback)
- [ ] Accessible, responsive, localized

**Effort:** L
**Value:** Medium (major DX/adoption boost; not load-bearing once OIDC + invites exist)
**Version impact:** Minor (additive hosted UI on top of OIDC provider)

**Dependencies:**
- Builds on **OIDC Provider (Downstream IdP for Apps)**.
- Custom-domain hosting reuses **Forward-Auth Proxy** protected-domains/portal-host infrastructure.

---

## [Embedder] Custom Roles & Entitlements API ("Access Levels")

**User Story:**
As a SaaS engineering team,
I want to define my application's own roles/entitlements per Organization and ask WeftID whether a user has a given access level,
So that I can model my product's access semantics in WeftID instead of inventing a parallel permission system in my own app.

**Context:**

WeftID's roles are fixed (`user`/`admin`/`super_admin`) — those govern *WeftID's* admin surface, not the embedder's application semantics. An embedder needs to define access levels meaningful to *their* product ("billing_manager", "viewer", "project_admin"), assign them to users/groups per Organization, and query them at request time. This is the authentik "Application Entitlements" / WorkOS FGA idea, scoped to embedding. The user explicitly asked for "define groups and access levels via the APIs."

**Design Notes:**

- Keep the existing WeftID platform roles for WeftID's own admin RBAC; add a **separate, embedder-defined entitlement layer** on top (don't overload the three platform roles).
- Per-Organization custom roles/entitlements, assignable to users and groups (reuse the group system + DAG effective membership for inheritance).
- An **authorization-check endpoint**: "does user U in Organization O have entitlement E?" — fast, cacheable, auditable. Optionally surfaced as a claim in the OIDC `groups`/`entitlements` scope.
- Decide scope of fine-grained-ness during grooming (role/entitlement labels vs. full relationship-based FGA — start with the former).

**Acceptance Criteria:**

- [ ] Define custom roles/entitlements per Organization via API (create/list/update/delete)
- [ ] Assign entitlements to users and groups; group assignments inherit via DAG effective membership
- [ ] `GET`/`POST` authorization-check endpoint: resolve whether a user has an entitlement, with low latency
- [ ] Entitlements exposable as OIDC claims (ties into the OIDC provider `entitlements`/`groups` scope)
- [ ] Distinct from WeftID's platform roles; embedder entitlements never grant WeftID admin access
- [ ] Assignment changes audited
- [ ] API-first; documented fields

**Effort:** L
**Value:** Medium (lets embedders model app access in WeftID; differentiator vs. raw SSO)
**Version impact:** Minor (additive entitlement layer + check endpoint)

**Dependencies:**
- Reuses the **group system** and DAG effective membership.
- Composes with **OIDC Provider** (entitlement claims) and the shared grant model.

---

## [Embedder] Official SDKs (Node + Python First)

**User Story:**
As a SaaS developer integrating WeftID,
I want official client libraries for my stack,
So that I can provision Organizations, issue portal links, verify webhooks, and run OIDC login in hours instead of hand-rolling REST calls.

**Context:**

Raw REST is a friction tax on adoption. Every comparable platform (WorkOS, Auth0, Stytch) ships first-party SDKs that wrap the management + auth APIs, handle auth/signing, and provide typed models. This item delivers official SDKs for the two most common embedder stacks first.

**Design Notes:**

- Generate from the existing OpenAPI schema where possible; hand-polish ergonomics (auth, pagination, webhook signature verification helpers, OIDC login helpers).
- Node/TypeScript and Python first; others (Go, Ruby, PHP) as follow-ups based on demand.
- Cover: Organizations API, platform-key auth, portal-link issuance, webhook signature verification, OIDC login/callback helpers.
- Versioned, published to npm/PyPI, with quickstart docs and runnable examples.

**Acceptance Criteria:**

- [ ] Node/TypeScript SDK: org lifecycle, portal links, webhook verification, OIDC login helpers; typed models; published to npm
- [ ] Python SDK: same surface; published to PyPI
- [ ] Generated from OpenAPI where practical, with ergonomic hand-polish
- [ ] Quickstart docs + runnable example apps for each SDK
- [ ] Versioning/release process documented; CI publishes on tag
- [ ] Webhook-signature and OIDC-callback helpers covered by tests

**Effort:** M
**Value:** Medium (compounds adoption; not load-bearing for the capability itself)
**Version impact:** N/A to the core app (separate published packages); tracks the API surface

**Dependencies:**
- Tracks the **Organizations API** (#1), **Platform keys** (#2), **Webhooks** (#3), and **OIDC Provider** surfaces.

---
