# Dashboard

The dashboard is your home page after signing in. It shows your identity, the applications you can access, and the groups you belong to.

## Your identity

The top of the dashboard displays your name, email address, role, user ID, tenant ID, and last sign-in time.

## My Apps

Lists the applications you can access. Click one to open it. You are signed in without entering separate credentials.

- **SAML applications** show their logo, or an auto-generated icon if none has been uploaded. WeftID shows a consent screen confirming your identity, then sends a signed SAML assertion to the application. This is called IdP-initiated SSO. See [SSO Flow](../admin-guide/service-providers/sso-flow.md).
- **OpenID Connect applications** open the application, which asks WeftID to sign you in. Because you are already signed in to WeftID, this usually happens without a prompt, apart from a one-time consent screen the first time you use the application.
- **Other web applications** that WeftID protects open directly. WeftID checks your access before the application loads.

If no applications are assigned to your groups, this section says **No applications available**. Contact your administrator to request access.

## My Groups

Lists the groups you belong to, including the group type (WeftID or IdP) and any parent groups in the hierarchy.
