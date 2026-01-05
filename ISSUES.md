# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

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
