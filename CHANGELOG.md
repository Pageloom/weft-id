# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
