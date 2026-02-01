# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [DEPS] ecdsa: CVE-2024-23342 - Minerva Timing Attack (Transitive)

**Package:** ecdsa (transitive via sendgrid)
**Installed Version:** 0.19.1
**Severity:** High (CVSS: 7.4)
**Advisory:** https://github.com/advisories/GHSA-wj6h-64fc-37mp

**Description:**
The python-ecdsa library is vulnerable to the Minerva timing attack on P-256 curve operations. The maintainers consider side-channel attacks out of scope because implementing side-channel-free code in pure Python is impossible.

**Exploitability in This Project:**
Low. This is a transitive dependency of sendgrid used for internal token signing. Exploitation requires controlling timing measurements of sendgrid API calls and gathering hundreds of samples.

**Remediation Options:**
1. Accept the risk (sendgrid's internal use is not directly exploitable)
2. Replace sendgrid with resend (this project already has resend as primary email backend)
3. Monitor for sendgrid updates that switch to pyca/cryptography

---

## [REFACTOR] Long Functions in User Management

**Found in:** `app/services/users.py`, `app/services/saml/auth.py`, `app/services/groups.py`
**Impact:** Medium

**Description:**
Several functions exceed 100 lines:
- `update_user()` in users.py (~130 lines)
- `process_saml_response()` in saml/auth.py (~130 lines)
- `sync_user_idp_groups()` in groups.py (~121 lines)

**Suggested Refactoring:**
Extract sub-operations into focused helper functions.

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | 1 dependency (transitive, no fix) |
| Medium | 1 | Refactoring |

**Last dependency audit:** 2026-02-01 (all direct dependencies are at safe versions)
