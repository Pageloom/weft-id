# User Lifecycle

Users in WeftId move through three possible states.

## Active

The default state. Active users can sign in and access their applications.

## Inactivated

Inactivated users cannot sign in. All their data is preserved, and they can be reactivated later. When a user is inactivated:

- Their session is terminated immediately
- All OAuth2 tokens are revoked (API access is cut off)
- They cannot request reactivation if a previous request was denied

An admin can inactivate any user except themselves, service users (linked to OAuth2 clients), or the last super admin.

### Reactivation

There are two ways to reactivate a user:

- **Admin-initiated** -- An admin reactivates the user directly from the user's detail page.
- **User-requested** -- The inactivated user submits a reactivation request. An admin must approve or deny it. Denied users cannot submit further requests.

Super admins have a special self-reactivation path: they prove email ownership to reactivate themselves without admin approval.

### Automatic inactivation

If configured in [Security > Sessions](../security/sessions.md), users who haven't been active for a set period are automatically inactivated. An admin must reactivate them before they can sign in again.

## Anonymized

Anonymization is a permanent, irreversible operation for GDPR right-to-be-forgotten requests. Only super admins can anonymize a user. When a user is anonymized:

- Their name is replaced with "[Anonymized] User"
- All email addresses are anonymized
- Two-step verification data is deleted
- Password is cleared

The user's ID and audit trail are preserved for compliance, but all personally identifiable information is removed.
