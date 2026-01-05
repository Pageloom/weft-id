# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## SAML IdP Simulator: Metadata Import Does Not Work Out-of-Box

**Found in:** SimpleSAMLphp configuration, SAML IdP setup flow

**Severity:** Medium (DX issue)

**Goal:** Make SAML IdP simulator setup as simple as: import metadata URL → enable → done.

**Current State:** Manual configuration required. The "Quick Import from Metadata URL" feature cannot be used because:

1. **Docker hostname mismatch** - Importing from `http://saml-idp:8080/...` (the only URL the app container can reach) results in SSO URLs containing `saml-idp` hostname, which the browser cannot resolve.

2. **Workaround tried** - Fetching metadata via `localhost:8080` doesn't work because from inside the app container, `localhost` refers to the container itself.

**Recommended Solution:** Configure SimpleSAMLphp to advertise `localhost:8080` URLs in its metadata regardless of how it's accessed. This requires setting an explicit `entityid` in `saml20-idp-hosted.php` that doesn't use `__DYNAMIC:1__`.

**Alternative:** Update docs to explain manual configuration is required for local dev IdP.

**Files to modify:**
- `simplesamlphp/saml20-idp-hosted.php` - Set explicit localhost entity ID and URLs

---

## SAML Error Page: Add SAML Response Debug Output

**Found in:** `app/templates/saml_error.html`

**Severity:** Low (DX improvement)

**Description:** When SAML validation fails, the error page shows a generic message. For debugging, it would be helpful to display the raw SAML response (base64 decoded) so developers can inspect what attributes were sent.

**Suggested fix:** Add a collapsible "Debug Info" section to `saml_error.html` that shows the SAML response XML when in development mode.

---

## SAML Edit Form: No Save Confirmation Feedback

**Found in:** SAML Identity Provider edit page

**Severity:** Low (UX issue)

**Description:** When saving changes on the IdP edit form (once the save bug is fixed), there's no visual feedback that the save succeeded. Users don't know if their changes were persisted.

**Suggested fix:** Add a flash message or toast notification on successful save.

---
