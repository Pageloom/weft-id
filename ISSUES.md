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

