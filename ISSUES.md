# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

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

