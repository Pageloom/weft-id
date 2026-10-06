# Roles and Permissions

WeftID has three roles, each with a different level of access.

## Super admin

Full access to all settings and management features. Super admins can:

- Manage all users, including creating other admins and super admins
- Configure identity providers (SAML, OIDC, and social sign-in)
- Register SAML service providers, forward-auth apps, and service accounts
- Change security settings (sessions, certificates, passwords, permissions, authentication policy)
- Manage the profile attribute catalog
- View the SAML debug log
- Everything an admin can do
- Reset user two-step verification and revoke individual passkeys
- Anonymize users (GDPR)

There must always be at least one super admin. The last super admin cannot be deactivated, anonymized, or demoted.

## Admin

Management access for day-to-day operations. Admins can:

- Create and manage users (but cannot create super admin accounts)
- Manage user [email addresses](email-management.md) (add, remove, promote, bulk operations)
- Manage groups and group membership
- Register OAuth2 / OIDC apps and configure client registration
- Manage domain routing (privileged domains)
- Configure branding
- View the event log and run exports
- Approve or deny reactivation requests

Admins cannot change security settings, manage identity providers, or register SAML, forward-auth, or service-account applications.

## Member

Standard access for end users. Members can:

- View their dashboard and launch applications
- Edit their profile (name, theme, timezone), if permitted by admin settings
- View their email addresses (managed by admins)
- Set up and manage their own two-step verification method and passkeys

Members cannot access any administrative pages.

## Role assignment

Roles are set when a user is created and can be changed later by an admin. Only super admins can promote users to the super admin role. Admins can assign the Admin or Member role.
