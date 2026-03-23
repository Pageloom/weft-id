# Dashboard

The dashboard is your home page after signing in. It shows your identity, the applications you can access, and the groups you belong to.

## Your identity

The top of the dashboard displays your name, email address, role, user ID, tenant ID, and last sign-in time.

## My Apps

Lists the applications you can access through single sign-on. Each application shows its name and logo (or an auto-generated icon if no logo has been uploaded). Click an application to launch it. WeftID shows a consent screen confirming your identity, then sends a signed SAML assertion to the application. You are signed in automatically without entering separate credentials.

This is called IdP-initiated SSO. For details on how the sign-on flow works, see [SSO Flow](../admin-guide/service-providers/sso-flow.md).

If no applications are assigned to your groups, this section is empty. Contact your administrator to request access.

## My Groups

Lists the groups you belong to, including the group type (WeftID or IdP) and any parent groups in the hierarchy.
