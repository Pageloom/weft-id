# Creating Groups

## Create a group

1. Navigate to **Groups**
2. Click **Create Group**
3. Enter a name and optional description
4. Click **Create**

The new group starts with no members and no parent-child relationships.

## Group types

Groups have one of two types:

- **WeftId** -- Manually managed. Admins add and remove members directly.
- **IdP** -- Synced from an external identity provider. Membership is read-only in WeftId and updates automatically during SAML sign-in.

IdP groups are created automatically when an identity provider sends group assertions during SSO. You cannot create IdP groups manually.
