# Creating Groups

## Add a group

1. Navigate to **Directory > Groups**
2. Click **Add Group**
3. Enter a name and optional description
4. Click **Add Group**

The new group starts with no members and no parent-child relationships. After creation, you can set an optional [custom acronym](../branding/index.md#custom-acronyms) and upload a logo on the group's **Details** tab.

## Group types

Groups have one of two types:

- **WeftID**: Manually managed. Admins add and remove members directly.
- **IdP**: Synced from an external identity provider. Membership is read-only in WeftID and updates automatically during SAML or OIDC sign-in.

IdP groups are created automatically when an identity provider sends group assertions (SAML) or a [group claim](../identity-providers/oidc-setup.md#group-claims) (OIDC) during SSO. You cannot create IdP groups manually.

## Delete a group

Open the group and select the **Delete** tab.

A group with parents or children cannot be deleted. Click **Remove All Relationships** first, or cut individual links in the groups graph.

Deleting a group removes all its memberships. The users themselves are not affected. Deletion cannot be undone.

IdP groups cannot be deleted while their identity provider exists. If the identity provider is deleted, its groups are marked **Invalid** and can be deleted once all members and relationships are removed.
