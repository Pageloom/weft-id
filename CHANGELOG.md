# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.4.0] - 2026-04-13

### Added

- SAML assertion debug log for troubleshooting authentication failures, accessible at **Audit > SAML Debug** with optional verbose logging for successful assertions
- SAML assertion replay prevention via Memcached (each assertion ID is cached and rejected on resubmission within its validity window)
- SAML assertion attribute resilience: missing optional attributes (first name, last name) no longer block sign-in. Existing user values are preserved.
- Automatic user attribute sync from the upstream IdP on each SAML sign-in (first name, last name updated when they differ)
- Failed SAML authentication attempts are now always logged with full diagnostic details
- SLO URL editing for metadata-imported service providers (previously read-only)

### Changed

- IdP-assigned users skip the password-setting step during onboarding and are directed to sign in through their identity provider
- SAML Debug Log moved from Settings to the Audit section in navigation
- Profile editing policy (`allow_users_edit_profile`) now enforced in the service layer, covering both web UI and API

### Security

- Added `max_length` constraints to all `Form()` parameters to prevent oversized input attacks (e.g., CPU exhaustion via Argon2 with megabyte-length passwords)
- Fixed XSS in assertion attribute preview where user-controlled data was interpolated via innerHTML without escaping
- Blocked SSRF via redirect following in SAML metadata URL fetch
- Fixed open redirect via unvalidated SAML RelayState parameter
- Replaced sequential integer nonces with cryptographically random tokens for email verification and password-reset links
- Removed unauthenticated check-email API endpoint (user enumeration vector)
- Removed super admin self-reactivation bypass; all reactivations now require admin approval
- Restricted B2B OAuth2 client management to super admins (was admin+)
- Rate-limited the account reactivation endpoint
- Certificate rotation grace period bounded to 0-90 days
- PII redacted from verbose SAML assertion event log metadata
- Docker containers now run as a non-root user
- Install script generates a random database password for the application user
- Install script sets `.env` file permissions to 600 (owner-only read/write)
- On-demand TLS certificate issuance restricted to registered tenant subdomains

## [1.3.0] - 2026-04-10

### Added

- Per-SP AES-256-GCM assertion encryption (opt-in) for SAML IdP connections, replacing CBC where enabled
- Auto-download of the Tailwind CSS binary on first use (no manual install required)

### Changed

- Renamed remaining "Loom Identity Platform" references to "WeftID" in X.509 signing certificates and the API schema title
- Role values now display as "Super Admin" / "Admin" / "User" instead of raw database values across all templates
- Consolidated repo root: moved compose files, shell scripts, and project management files into dedicated directories; retired shell scripts in favor of `make` targets

### Security

- Fixed CBC padding oracle vulnerability on SAML ACS endpoints
- Scoped the SAML ACS rate limit key per tenant to prevent cross-tenant denial-of-service via shared egress IPs
- Updated cryptography from 46.0.6 to 46.0.7

## [1.2.0] - 2026-04-05

### Added

- Streamlined sign-in flow that routes directly to auth method without email verification, with tenant opt-in setting to preserve the old discovery flow
- Bulk user operations from the user list: inactivate/reactivate, add to group, add secondary emails, and change primary email with dry-run SP assertion impact preview
- User audit export as password-encrypted XLSX (Users, Group Memberships, App Access sheets)
- Audit log XLSX export with optional date range, replacing the JSON export
- Audit event visibility tiers (security, admin, operational, system) with color-coded UI toggles and API filter support
- Resend invitation email for pending users with nonce-based link invalidation
- Branded email headers with tenant logo and name across all 15 outbound emails, plus a Pageloom footer
- User list filter panel redesigned as floating popover with IS/IS NOT toggle, filter negation, group hierarchy inclusion, and tinted active-state borders
- Contextual documentation links on admin pages (information-circle icon linking to relevant docs)
- Icons on action bar buttons

### Changed

- Email management is now admin-only; self-service email add/remove/promote/verify removed from user accounts
- Sign-in flow defaults to skipping email verification (old behavior available via `require_email_verification_for_login` tenant setting)
- Consolidated tenant name and site title into a single field (`tenants.name`)
- Standardized product name to "WeftID" across all user-facing copy
- Renamed "MFA" to "two-step verification" in emails and exports
- Authorization denial logs moved from tenant audit trail to application logs
- Removed `weftid` management script in favor of documented Docker Compose commands

### Fixed

- Fixed XSS in bulk email template where user-controlled names were interpolated via innerHTML
- Fixed group picker missing group_type data and modal backdrop issues
- Fixed export file passwords persisting in the database after file expiry (now redacted)
- Fixed flaky test_claim_next_task in parallel test runs

### Security

- Set-password and invitation links are now one-time use via nonce-based invalidation (migration 0023)
- Bounded bulk operation list fields to max 5000 items to prevent resource exhaustion
- Export file passwords are redacted from the database after the download window expires

## [1.1.0] - 2026-03-21

### Added

- Group assertion scope setting to control which groups are shared in SAML assertions (access-relevant, trunk, or all) with per-SP override and consent screen disclosure
- Email deliverability verification CLI (`python -m app.cli.verify_email`) for checking SPF, DKIM, and DMARC before tenant provisioning
- Self-hosting upgrade and backup documentation with full rollback procedure

### Changed

- Restructured self-hosting guide as a numbered first-setup flow with install directory guidance
- Self-hosting docs now emphasize that SECRET_KEY and POSTGRES_PASSWORD are irrecoverable
- Standardized password error messages across all password templates
- Rebuilt documentation site with Zensical 0.0.28

### Fixed

- Fixed production Docker image showing "dev" as the version when the build arg was not explicitly passed
- Fixed incorrect role list in self-hosting backup documentation (removed unused migrator role)

### Security

- Fixed LIKE wildcard injection in search queries where %, _, and \ in search terms were interpreted as SQL wildcards instead of matching literally
- Added rate limiting to password change endpoints (5 per user per hour, 10 per IP per hour)
- Fixed content injection via unvalidated query parameters in password-related templates

## [1.0.4] - 2026-03-21

### Added

- About WeftID page in admin settings showing the running version, documentation links, and project info
- API endpoint at `/api/v1/settings/version` for retrieving version information
- Documentation for password policy settings, HIBP breach detection, forced password reset, and self-service password flows

### Changed

- Updated group hierarchy documentation with shift+drag subtree move and tooltip positioning details

### Fixed

- Fixed Postgres 18 data loss on container restart caused by a PGDATA path change in Postgres 18
- Fixed version detection in the dev Docker environment when the app directory is bind-mounted

## [1.0.3] - 2026-03-21

### Fixed

- Fixed missing `defusedxml` runtime dependency that could cause import errors in production

## [1.0.2] - 2026-03-21

### Fixed

- Fixed missing `httpx` runtime dependency that could cause import errors in production

## [1.0.1] - 2026-03-21

### Changed

- Replaced Poetry with pip in the production Dockerfile, eliminating ~3 minutes of arm64 cross-compile time under QEMU emulation. A CI workflow now keeps a pinned requirements file in sync with `poetry.lock`.
- Bumped Docker GitHub Actions to latest majors (setup-buildx v4, login v4, metadata v6, build-push v7)
- Bumped uvicorn from 0.41.0 to 0.42.0
- Bumped resend from 2.23.0 to 2.26.0
- Bumped zensical from 0.0.24 to 0.0.28
- Bumped ruff from 0.15.5 to 0.15.7

## [1.0.0] - 2026-03-20

Initial release of WeftID, a multi-tenant identity federation platform.

### Added

**Identity Federation**
- SAML 2.0 identity provider integration (Okta, Entra ID, Google Workspace, generic SAML)
- OAuth2 identity provider support
- Per-connection SAML entity IDs (stable URN-based)
- Domain routing for multi-IdP tenants
- JIT user provisioning from SAML identity providers

**SAML Identity Provider**
- SAML 2.0 Identity Provider for downstream service providers
- SP-initiated SSO with user consent screen
- Per-SP signing certificates with configurable lifetime and auto-rotation
- SAML assertion encryption (IdP-side for downstream SPs, SP-side decryption for upstream)
- Single Logout (SLO) for downstream service providers
- Per-SP NameID format configuration
- Opt-in group claims in SAML assertions with per-SP attribute mapping
- Dynamic attribute declarations in SAML metadata

**Authentication & Security**
- Multi-factor authentication (TOTP with backup codes, admin reset)
- Password strength policy with zxcvbn entropy scoring and HIBP breach checking
- Password lifecycle hardening (expiry, reuse prevention, admin-forced reset)
- Self-service forgot password flow with stateless time-windowed tokens
- Rate limiting on authentication endpoints
- CSRF protection with per-request tokens
- Content Security Policy with script nonces
- HKDF-based key derivation for all cryptographic operations
- Secure session management with configurable timeouts

**User Management**
- User lifecycle management (creation, inactivation, reactivation with approval flow)
- Invitation-based onboarding with email verification
- User profile with dark mode and timezone preferences
- Privileged email domains with automatic group assignment

**Groups**
- Group system with DAG hierarchy (multiple parents, cycle prevention via closure table)
- Group-based service provider access control with "available to all users" mode
- Effective membership queries (direct and inherited)
- Interactive group graph visualization with dagre layout and DB-persisted positions
- IdP-synced groups with umbrella and assertion sub-groups
- Per-group logo upload and customizable acronyms
- Bulk member management

**Service Provider Management**
- Two-step SP registration with trust establishment
- SP lifecycle management (enable, disable, delete)
- SP metadata lifecycle (import, refresh, manual entry)
- SP logo/avatar support
- User access count on SP list view

**Tenant & Branding**
- Multi-tenant data isolation with Row-Level Security
- Tenant branding with custom logo upload and generated mandala fallback
- Custom site title with nav bar visibility toggle

**Audit & Operations**
- Comprehensive audit logging with request metadata
- Activity tracking for read operations
- Data export system with background job processing
- Integration management (API keys with lifecycle controls)

**Infrastructure**
- RESTful API (v1) for all management operations with OAuth2 bearer token auth
- Production Docker Compose with Caddy for automatic HTTPS (on-demand TLS)
- Self-hosting install script with secret generation
- Tenant provisioning CLI
- Forward-only migration system with baseline schema
- Health check endpoint and bare domain rejection
- Documentation site served at /docs
- GitHub Actions CI (lint, format, type check, tests, E2E)
- GHCR publish workflow with multi-arch Docker images (amd64, arm64)
