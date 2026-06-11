# User Lifecycle

Users in WeftID move through three possible states.

## Active

The default state. Active users can sign in and access their applications.

An active user may also be in a **password reset required** state. This happens when an admin forces a password reset or when a [breach detection](../security/passwords.md#breach-detection) check finds a compromised password. The user can still sign in, but must choose a new password before reaching the dashboard.

## Deactivated

Deactivated users cannot sign in. All their data is preserved, and they can be reactivated later. When a user is deactivated:

- Their session is terminated immediately
- All OAuth2 tokens are revoked (API access is cut off)
- They cannot request reactivation if a previous request was denied

An admin can deactivate any user except themselves, service users (linked to OAuth2 clients), or the last super admin.

### Bulk deactivation and reactivation

Admins can deactivate or reactivate multiple users at once from the user list:

1. Select users using the checkboxes.
2. Click **Deactivate** or **Reactivate** in the action bar.
3. A preview shows which users are eligible and which will be skipped (with reasons).
4. Confirm to start a background job that processes each user individually.

Skipped users include those already in the target state, service users, the last super admin, and anonymized users. Per-user errors do not fail the entire job.

### Reactivation

There are three ways to reactivate a user:

**Admin-initiated.** An admin reactivates the user directly from the user's detail page. No request or approval needed.

**User-requested.** A deactivated user who tries to sign in sees a message explaining their account is deactivated. They can click **Request Reactivation** to submit a request. When they do:

1. All admins receive an email notification with the user's name and email.
2. The request appears under **Admin > Todo > Reactivation**.
3. An admin reviews the request and clicks **Approve** or **Deny**.
4. The user receives an email with the decision.

Approved users can sign in immediately. Denied users cannot submit another request. They must contact their administrator, who can still reactivate them manually from the user detail page.

Past decisions are visible in the reactivation history view (**Admin > Todo > Reactivation > View History**).

### Account recovery via forgot-password

Deactivated users who use the forgot-password flow will see their deactivation status after proving email ownership. From there they can request reactivation directly.

### Automatic deactivation

If configured in [Security > Sessions](../security/sessions.md), users who haven't been active for a set period are automatically deactivated. An admin must reactivate them before they can sign in again.

When the daily job deactivates at least one user, every active admin and super admin receives an email listing the affected users (name, email, last activity date) and the configured inactivity threshold, so they can reactivate any account that was deactivated in error.

Any authenticated action counts as activity: signing in, triggering an SSO flow, viewing pages, or making API calls.

### IdP-assigned user onboarding

Users created via SAML JIT provisioning skip the password-setting step during onboarding. After verifying their email address, they are redirected to sign in through their identity provider instead of being prompted to create a password.

## Forced profile completion

If your tenant requires certain [profile attributes](../security/user-attributes.md)
and a user is missing values, an admin can require them to complete their profile
before they can use the site.

1. Navigate to **Admin > Todo > User attributes**. Each user is listed with the
   missing attributes split by whether the user can fill them (unlocked) or only
   an admin can (locked).
2. Select users with missing unlocked attributes.
3. Click **Force profile completion**.

Flagged users land on their profile page on the next request with the required
fields highlighted. They cannot navigate elsewhere until every unlocked-required
attribute has a value. The gate also blocks SAML SSO to downstream applications.

Users whose only missing values are locked attributes cannot be force-completed
(they would never be able to clear the gate). Fill those values from the user
detail page instead.

## Anonymized

Anonymization is a permanent, irreversible operation for GDPR right-to-be-forgotten requests. Only super admins can anonymize a user. When a user is anonymized:

- Their name is replaced with "[Anonymized] User"
- All email addresses are anonymized
- Two-step verification data is deleted (TOTP secret, backup codes, and all passkeys)
- Password is cleared

The user's ID and audit trail are preserved for compliance, but all personally identifiable information is removed.
