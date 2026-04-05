# Membership Management

## Adding members

There are two ways to add members to a group.

**From the group's members page.** The **Members** tab on a group's detail page lists current members with search, filtering, and pagination.

1. Click **Add Members**
2. Search for users by name or email (only non-members are shown)
3. Select one or more users
4. Click **Add**

Small batches are processed immediately. The page shows how many members were added.

**From the user list.** Select users from the main user list, then click **Add to Group** in the action bar.

1. Select users using the checkboxes
2. Click **Add to Group**
3. Pick a group from the dropdown
4. A preview shows eligible users and any that will be skipped (already members)
5. Confirm to start a background job

The job result is available under **Account > Background Jobs**.

## Removing members

Select one or more members using the checkboxes on the group's members page, then click **Remove** in the action bar.

## IdP groups

Members of IdP-type groups are managed automatically by the identity provider. Membership updates each time a user signs in via SAML and the IdP includes group assertions. You cannot manually add or remove members from IdP groups. Bulk assignment also rejects IdP groups.

## Inherited membership

Group membership is explicit. A user who is a member of a parent group is not automatically a member of its children. However, access to service providers can be controlled at any level in the hierarchy. See [Group-Based Access](group-based-access.md).
