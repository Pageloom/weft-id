# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Tenant Security Settings Form Returns 404 When Saving

**Found in:** app/templates/settings_tenant_security.html:30

**Severity:** High

**Description:** The tenant security settings form submits to an incorrect URL, causing all save attempts to return 404 errors. Users cannot update security settings through the web interface.

**Evidence:**
- Template form action at app/templates/settings_tenant_security.html:30:
  ```html
  <form method="post" action="/settings/tenant-security/update">
  ```
- Actual route in app/routers/settings.py:
  - Router prefix: `/admin` (line 24)
  - Route path: `/security/update` (line 143)
  - Full URL: `/admin/security/update`

**Impact:**
- Complete breakage of tenant security settings update functionality
- Users see 404 error when attempting to save security settings
- Critical feature is non-functional in production

**Root Cause:**
Template uses hardcoded URL path that doesn't match the router's prefix + route combination. The form was likely created before the router prefix was set to `/admin`, or the prefix was changed without updating the template.

**Why Tests Didn't Catch This:**
All existing tests in tests/test_routers_settings.py (lines 420-539) directly POST to the correct URL `/admin/security/update` using the test client. None of them:
1. Render the actual template
2. Parse the form action attribute
3. Verify the template points to the correct endpoint

This is a classic integration gap between template rendering and route testing.

**Suggested Fix:**

**Option 1: Fix the template URL (Recommended)**
Change app/templates/settings_tenant_security.html:30 from:
```html
<form method="post" action="/settings/tenant-security/update">
```
to:
```html
<form method="post" action="/admin/security/update">
```

**Option 2: Use URL generation helper (More robust)**
If Jinja2 has access to a `url_for` helper, use:
```html
<form method="post" action="{{ url_for('update_admin_security') }}">
```

**Files that need modification:**
- app/templates/settings_tenant_security.html (line 30) - fix form action URL

**Recommended tests to add:**
1. Integration test that renders the template and verifies form action URL
2. End-to-end Playwright test that actually submits the form and verifies success

---

## Event Logging Completely Broken - Hash Mismatch Between Python and PostgreSQL

**Found in:** app/utils/request_metadata.py and db-init/00015_event_log_metadata.sql

**Severity:** Critical

**Description:** ALL event logging has been broken since migration 00015 was deployed. Events are not being recorded in the database due to foreign key constraint violations. The metadata hash computed by Python code doesn't match the hash computed by PostgreSQL during migration, causing INSERT failures.

**Evidence:**
- Application logs show repeated failures:
  ```
  Failed to log event: the last operation didn't produce records (command status: INSERT 0 1)
  ```
- Database logs show foreign key violations:
  ```
  ERROR:  insert or update on table "event_logs" violates foreign key constraint "fk_event_logs_metadata_hash"
  DETAIL:  Key is not present in table "event_log_metadata".
  ```
- Python hash computation (app/utils/request_metadata.py):
  ```python
  json_str = json.dumps(metadata, sort_keys=True, separators=(',', ':'))
  hash_val = hashlib.md5(json_str.encode()).hexdigest()
  # Result: "14f2852559f6e4cd13cf229dab01e31d" (compact JSON, no spaces)
  ```
- PostgreSQL hash computation (db-init/00015_event_log_metadata.sql:82):
  ```sql
  system_metadata_hash := md5(system_metadata_obj::text);
  -- Result: "ea545ece1092debab806304abb82ed6c" (JSON with spaces after colons)
  ```

**Impact:**
- **Complete audit trail failure** - no events have been logged since migration 00015
- Security incidents cannot be investigated - no record of who did what
- Compliance violations - audit requirements not being met
- Silent failures - operations succeed but logging fails silently (caught by try/except)
- Data integrity - some events were logged before migration (10 events exist), creating inconsistent audit trail

**Root Cause:**
JSON serialization format mismatch between Python and PostgreSQL:
1. Python's `json.dumps(separators=(',', ':'))` produces: `{"device":null,"remote_address":null,...}` (compact, no spaces)
2. PostgreSQL's `jsonb::text` produces: `{"device": null, "remote_address": null,...}` (spaces after colons)
3. MD5 hashes of these different strings don't match
4. Migration 00015 backfilled existing events with PostgreSQL-computed hashes
5. New events try to INSERT with Python-computed hashes
6. Foreign key constraint fails because the hash doesn't exist in event_log_metadata table

**Why Tests Didn't Catch This:**
1. No integration tests that actually write events to a real database with RLS enabled
2. No tests that verify event_log records are created after service operations
3. No tests that compare Python hash computation with PostgreSQL hash computation
4. Migration was tested in isolation, not with the running application code

**Suggested Fix:**

**Option 1: Fix Python to match PostgreSQL format (Recommended)**
Change app/utils/request_metadata.py to produce JSON with spaces after colons:
```python
# Instead of:
json_str = json.dumps(metadata, sort_keys=True, separators=(',', ':'))

# Use:
json_str = json.dumps(metadata, sort_keys=True, separators=(', ', ': '))
```
This will make Python produce the same JSON format as PostgreSQL's `jsonb::text`.

**Option 2: Fix PostgreSQL migration to match Python format**
Regenerate all metadata hashes in the database using compact JSON format. This requires:
1. Creating a new migration to recompute all hashes
2. Using a PostgreSQL function that produces compact JSON (more complex)
3. Updating all existing event_logs.metadata_hash references

**Option 3: Use PostgreSQL function for hash computation**
Create a PostgreSQL function that computes hashes and call it from Python via SQL.
This ensures consistency but adds complexity.

**Files that need modification:**
- app/utils/request_metadata.py (line ~20-30) - fix separators parameter in json.dumps()

**Required tests:**
1. Unit test: Verify Python hash matches PostgreSQL hash for same metadata
2. Integration test: Verify event_log records are created when service functions execute writes
3. Integration test: Verify metadata deduplication works (same metadata = same hash)
4. Migration test: Verify backfill produces correct hashes

**Immediate Remediation Steps:**
1. Fix the hash computation in Python code
2. Run a data migration to recompute existing hashes OR clear and regenerate event_log_metadata table
3. Verify events start logging successfully
4. Consider backfilling missing events from application logs if critical

---

