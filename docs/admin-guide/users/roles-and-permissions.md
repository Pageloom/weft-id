# Roles and Permissions

WeftId has three roles, each with a different level of access.

## Super admin

Full access to all settings and management features. Super admins can:

- Manage all users, including creating other admins and super admins
- Configure identity providers
- Register and manage service providers
- Change security settings (sessions, certificates, permissions)
- Manage privileged domains
- View audit logs
- Configure branding
- Reset user MFA
- Anonymize users (GDPR)

There must always be at least one super admin. The last super admin cannot be inactivated or deleted.

## Admin

Management access for day-to-day operations. Admins can:

- Create and manage users (but cannot create super admin accounts)
- Manage groups and group membership
- Configure branding
- Manage privileged domains
- View audit logs
- Approve or deny reactivation requests

Admins cannot change security settings or manage identity providers.

## User

Standard access for end users. Users can:

- View their dashboard and launch applications
- Edit their profile (name, theme, timezone), if permitted by admin settings
- Add email addresses to their account, if permitted by admin settings
- Set up and manage their own MFA

Users cannot access any administrative pages.

## Role assignment

Roles are set when a user is created and can be changed later by an admin. Only super admins can promote users to the super admin role. Admins can assign the admin or user role.
