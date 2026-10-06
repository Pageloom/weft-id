# Membership Management

## Adding members

There are three ways to add members to a group.

**From the group's members page.** The **Members** tab on a group's detail page lists current members with search, filtering, and pagination.

1. Click **Add Members**
2. Search for users by name or email (only non-members are shown)
3. Select one or more users
4. Click **Add**

Members are added immediately. The page shows how many were added.

**From the user list.**

1. Select users using the checkboxes
2. Click **Add to Group**
3. Pick a group from the dropdown
4. A preview shows eligible users and any that will be skipped (already members)
5. Confirm to start a background job

The job result is available under **User Settings > Background Jobs**.

**From a user's detail page.** On the user's **Groups** tab, pick a group under **Add to Group** and click **Add**. To add the user to several groups at once, select them in the second list and click **Bulk Add**.

## Removing members

Select one or more members using the checkboxes on the group's members page, then click **Remove** in the action bar.

## IdP groups

Members of IdP-type groups are managed automatically by the identity provider. Membership updates each time a user signs in through the IdP and it includes group assertions (SAML) or a group claim (OIDC). You cannot manually add or remove members from IdP groups. Bulk assignment also rejects IdP groups.

## Inherited membership

Membership flows up the hierarchy. Members of a child group are inherited members of every ancestor group. The **Members** tab lists direct members first, then inherited members under **Inherited via child groups**. The member count shows both.

Membership does not flow down. A member of a parent group is not a member of its children.

Access to applications follows inherited membership. See [Group-Based Access](group-based-access.md).
