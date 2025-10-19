# TODO - Future Improvements

## Security Enhancements

### Privileged Domain Verification
**Priority**: High
**Impact**: Security

**Current State**:
- Super admins can add privileged email domains (e.g., @company.com)
- Emails from these domains are auto-verified without requiring email verification
- No verification that the tenant actually controls the domain

**Security Risk**:
- A malicious admin could add domains they don't own (e.g., @gmail.com, @microsoft.com)
- Any user with an email from that domain would be auto-verified
- This bypasses the email verification security layer

**Proposed Solution - DNS TXT Record Verification**:

1. **Database Changes**:
   - Add `verification_token` (random 32-char string)
   - Add `verified` (boolean, default false)
   - Add `verified_at` (timestamp)
   - Only allow auto-verification for domains where `verified = true`

2. **Verification Process**:
   - When admin adds a privileged domain, generate a random token
   - Show instructions: "Add this TXT record to your DNS: `loom-verify=<token>`"
   - Provide "Verify Domain" button
   - On click, query DNS for TXT record on the domain
   - If `loom-verify=<token>` found, mark domain as verified
   - Only verified domains allow auto-verification of emails

3. **Implementation Files**:
   - Migration: `db-init/00009_domain_verification.sql`
   - Utility: `app/utils/dns.py` (using dnspython package)
   - Database: Update `app/database/settings.py`
   - Routes: Add verification endpoint to settings router
   - UI: Update settings template to show verification status

4. **Similar Implementations**:
   - Google Workspace domain verification
   - Microsoft 365 domain verification
   - Slack workspace domain verification

**Dependencies**:
- `dnspython` package for DNS queries

**Estimated Effort**: 4-6 hours

---

## Feature Ideas

<!-- Add future feature ideas here -->

## Technical Debt

<!-- Add technical debt items here -->

## Documentation

<!-- Add documentation needs here -->
