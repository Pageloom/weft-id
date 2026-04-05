# User Lifecycle

Users in WeftID move through three possible states.

## Active

The default state. Active users can sign in and access their applications.

An active user may also be in a **password reset required** state. This happens when an admin forces a password reset or when a [breach detection](../security/passwords.md#breach-detection) check finds a compromised password. The user can still sign in, but must choose a new password before reaching the dashboard.

## Inactivated

Inactivated users cannot sign in. All their data is preserved, and they can be reactivated later. When a user is inactivated:

- Their session is terminated immediately
- All OAuth2 tokens are revoked (API access is cut off)
- They cannot request reactivation if a previous request was denied

An admin can inactivate any user except themselves, service users (linked to OAuth2 clients), or the last super admin.

### Bulk inactivation and reactivation

Admins can inactivate or reactivate multiple users at once from the user list:

1. Select users using the checkboxes.
2. Click **Inactivate** or **Reactivate** in the action bar.
3. A preview shows which users are eligible and which will be skipped (with reasons).
4. Confirm to start a background job that processes each user individually.

Skipped users include those already in the target state, service users, the last super admin, and anonymized users. Per-user errors do not fail the entire job.

### Reactivation

There are three ways to reactivate a user:

**Admin-initiated.** An admin reactivates the user directly from the user's detail page. No request or approval needed.

**User-requested.** An inactivated user who tries to sign in sees a message explaining their account is inactivated. They can click **Request Reactivation** to submit a request. When they do:

1. All admins receive an email notification with the user's name and email.
2. The request appears under **Admin > Todo > Reactivation**.
3. An admin reviews the request and clicks **Approve** or **Deny**.
4. The user receives an email with the decision.

Approved users can sign in immediately. Denied users cannot submit another request. They must contact their administrator, who can still reactivate them manually from the user detail page.

Past decisions are visible in the reactivation history view (**Admin > Todo > Reactivation > View History**).

**Super admin self-reactivation.** Super admins can reactivate themselves by verifying their email address. No admin approval is needed. After verification, the super admin can sign in immediately if they have a password, or must contact another admin to set one up.

### Account recovery via forgot-password

Inactivated users who use the forgot-password flow will see their inactivation status after proving email ownership. From there they can request reactivation directly.

### Automatic inactivation

If configured in [Security > Sessions](../security/sessions.md), users who haven't been active for a set period are automatically inactivated. An admin must reactivate them before they can sign in again.

Any authenticated action counts as activity: signing in, triggering an SSO flow, viewing pages, or making API calls.

## Anonymized

Anonymization is a permanent, irreversible operation for GDPR right-to-be-forgotten requests. Only super admins can anonymize a user. When a user is anonymized:

- Their name is replaced with "[Anonymized] User"
- All email addresses are anonymized
- Two-step verification data is deleted
- Password is cleared

The user's ID and audit trail are preserved for compliance, but all personally identifiable information is removed.
