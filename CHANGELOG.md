# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-03-14

Initial release of WeftId, a multi-tenant identity federation platform.

### Added

- SAML 2.0 identity provider integration (Okta, Entra ID, Google Workspace, generic SAML)
- SAML 2.0 Identity Provider for downstream service providers with per-SP signing certificates
- SAML assertion encryption (SP-side decryption and IdP-side encryption for downstream SPs)
- OAuth2 identity provider support
- Multi-factor authentication (TOTP with backup codes)
- User lifecycle management (creation, inactivation, reactivation)
- Group system with DAG hierarchy and group-based service provider access control
- Comprehensive audit logging and activity tracking
- Multi-tenant data isolation with Row-Level Security
- RESTful API (v1) for all management operations
- Docker-based deployment with automatic schema migrations
- Documentation site served at /docs
