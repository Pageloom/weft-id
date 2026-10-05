# Creating Users

## Manual creation

1. Navigate to **Directory > Users**
2. Click **Add User**
3. Enter the user's first name, last name, and email address
4. Select a role: Member, Admin, or Super Admin
5. Optionally fill in any
   [profile attributes](../security/user-attributes.md) that your tenant has enabled.
   Leave fields blank to let the user fill them in later. Admins can pre-fill
   locked attributes here.
6. Click **Create User**

The user receives an invitation email with a verification link. After verifying their email, they set a password and can sign in. Invitation links are one-time use.

If a user hasn't completed onboarding, you can resend the invitation from their profile page. See [Resending invitations](email-management.md#resending-invitations).

## Just-in-time provisioning

When an identity provider has JIT provisioning enabled, users are created automatically on their first sign-in. This applies to SAML providers and to OIDC and social sign-in connections. WeftID creates the account from the email, first name, and last name the provider sends.

JIT-provisioned users get the **Member** role.

Any standard [profile attributes](../security/user-attributes.md) with **Mirror
from IdP** enabled are populated from the same sign-in data. Required attributes
that the IdP does not send leave the user with an incomplete profile (see
[user lifecycle](user-lifecycle.md) for the force-completion workflow).

## Auto-assignment to groups

If the user's email domain matches a [privileged domain](../identity-providers/privileged-domains.md) with linked groups, the user is automatically added to those groups at creation time. This applies to both manually created users and JIT-provisioned users.
