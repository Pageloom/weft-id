# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 1 | Outbound Timeouts |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-08 (structural IA review, 2 direct fixes, 6 issues resolved)

---

## Outbound Timeouts: SendGrid client missing request timeout

**Found in:** `app/utils/email_backends/sendgrid_backend.py:17`
**Severity:** Low
**Principle Violated:** Outbound Timeouts
**Description:** The `SendGridAPIClient` constructor does not accept a `timeout` parameter, and the underlying `python_http_client` transport has no default timeout. If the SendGrid API becomes slow or unresponsive, the calling thread blocks indefinitely, which could cascade into worker exhaustion.
**Evidence:**
```python
self.client = SendGridAPIClient(settings.SENDGRID_API_KEY)
```
**Impact:** A slow or unresponsive SendGrid API could hang request-handling threads for email-sending operations (invitations, password resets, MFA codes), eventually exhausting the worker pool.
**Suggested fix:** Set timeout on the underlying HTTP client after construction:
```python
self.client = SendGridAPIClient(settings.SENDGRID_API_KEY)
self.client.timeout = 10
```

---

