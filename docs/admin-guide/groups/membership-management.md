# Membership Management

## Adding members

From a group's detail page, the **Members** tab lists current members with search, filtering, and pagination.

To add members:

1. Click **Add Members**
2. Search for users by name or email
3. Select one or more users
4. Click **Add**

You can also add a user to multiple groups at once from the user's detail page.

## Removing members

Select one or more members using the checkboxes, then click **Remove** in the action bar. You can also remove a single member from the member row.

## IdP groups

Members of IdP-type groups are managed automatically by the identity provider. Membership updates each time a user signs in via SAML and the IdP includes group assertions. You cannot manually add or remove members from IdP groups.

## Inherited membership

Group membership is explicit. A user who is a member of a parent group is not automatically a member of its children. However, access to service providers can be controlled at any level in the hierarchy. See [Group-Based Access](group-based-access.md).
