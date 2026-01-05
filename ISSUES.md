# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## API-First: SAML Identity Provider Management has no API endpoints

**Found in:** `app/services/saml.py` (entire service)
**Severity:** High
**Principle Violated:** API-First
**Description:** All SAML Identity Provider management operations are web-only. No API endpoints exist for CRUD operations on IdPs.

**Missing API endpoints:**
- `GET /api/v1/saml/identity-providers` - List IdPs
- `GET /api/v1/saml/identity-providers/{idp_id}` - Get IdP details
- `POST /api/v1/saml/identity-providers` - Create IdP
- `PATCH /api/v1/saml/identity-providers/{idp_id}` - Update IdP
- `DELETE /api/v1/saml/identity-providers/{idp_id}` - Delete IdP
- `POST /api/v1/saml/identity-providers/{idp_id}/enable` - Enable/disable IdP
- `POST /api/v1/saml/identity-providers/{idp_id}/set-default` - Set default IdP
- `POST /api/v1/saml/identity-providers/import` - Import from metadata URL
- `POST /api/v1/saml/identity-providers/{idp_id}/refresh` - Refresh metadata
- `GET /api/v1/saml/sp-metadata` - Get SP metadata
- `GET /api/v1/saml/sp-certificate` - Get/create SP certificate

**Impact:** Third-party integrations and automation cannot manage SAML configuration programmatically
**Root Cause:** SAML Phase 1 focused on web UI implementation
**Suggested fix:** Create `app/routers/api/v1/saml.py` with RESTful endpoints for all IdP operations

---

## API-First: User state operations missing API endpoints

**Found in:** `app/services/users.py`
**Severity:** Medium
**Principle Violated:** API-First
**Description:** User inactivation, reactivation, and anonymization are web-only operations.

**Missing API endpoints:**
- `POST /api/v1/users/{user_id}/inactivate` - Inactivate user
- `POST /api/v1/users/{user_id}/reactivate` - Reactivate user
- `POST /api/v1/users/{user_id}/anonymize` - Anonymize user (GDPR)

**Impact:** Cannot automate user lifecycle management via API
**Root Cause:** Oversight during user management implementation
**Suggested fix:** Add endpoints to `app/routers/api/v1/users.py`

---

## API-First: Event log has no API endpoints

**Found in:** `app/services/event_log.py`
**Severity:** Medium
**Principle Violated:** API-First
**Description:** Event log viewing is web-only. No API endpoints exist for audit log access.

**Missing API endpoints:**
- `GET /api/v1/events` - List events (with filters)
- `GET /api/v1/events/{event_id}` - Get event details

**Impact:** Cannot integrate audit logs with external SIEM or monitoring systems
**Root Cause:** Event log UI was implemented without corresponding API
**Suggested fix:** Create `app/routers/api/v1/events.py`

---

## API-First: Exports and background tasks have no API endpoints

**Found in:** `app/services/exports.py`, `app/services/bg_tasks.py`
**Severity:** Medium
**Principle Violated:** API-First
**Description:** Export creation, listing, and download are web-only. Background job management has no API.

**Missing API endpoints:**
- `POST /api/v1/exports` - Create export task
- `GET /api/v1/exports` - List exports
- `GET /api/v1/exports/{export_id}/download` - Download export file
- `GET /api/v1/jobs` - List user's background jobs
- `GET /api/v1/jobs/{job_id}` - Get job details
- `DELETE /api/v1/jobs` - Delete completed jobs

**Impact:** Cannot automate data export workflows
**Root Cause:** Export feature was web-first implementation
**Suggested fix:** Create `app/routers/api/v1/exports.py` and `app/routers/api/v1/jobs.py`

---

