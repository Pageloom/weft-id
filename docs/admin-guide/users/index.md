# User Management

Manage the users in your WeftID tenant. Create users manually or let them self-register through an identity provider. Control their lifecycle from active to inactive and back.

- [Creating Users](creating-users.md)
- [Email Management](email-management.md) — Add, remove, promote emails; bulk operations
- [User Lifecycle](user-lifecycle.md) — Active, inactive, reactivation workflows
- [Roles and Permissions](roles-and-permissions.md) — Super admin, admin, and user roles

## User list

Navigate to **Users > User List** to see all users in your tenant. The list shows name, email, role, status, last activity, creation date, authentication method, and group count.

### Searching

Use the search bar to find users by name or email address.

### Sorting

Click any column header to sort by that field. Click again to reverse the order. Sortable columns: name, email, role, status, last activity, and created date.

### Filtering

Click **Filters** to open the filter panel. Combine multiple filters to narrow results.

| Filter | Options |
|--------|---------|
| **Role** | Member, Admin, Super Admin |
| **Status** | Active, Inactivated, Anonymized |
| **Auth Method** | Lists all authentication methods in use (Password, specific IdPs) |
| **Domain** | Email domains in use. Privileged domains are marked with a star. |
| **Group** | Select a group. Optionally check **Include child groups** to include members of descendant groups in the hierarchy. |

Each filter has an **is/is not** toggle. Click it to negate the filter. For example, set Role to "Admin" with "is not" to see everyone who is *not* an admin.

Active filters are indicated by a **Filtered results** label next to the Filters button. Click **Clear filters** to reset.

Filter state and page size preferences are saved in your browser and persist across sessions.

### Bulk selection

Use checkboxes to select users for [bulk email operations](email-management.md#bulk-email-operations). After checking users on the current page, you can click **Select all N matching users** to extend the selection to every user matching the current search and filters, even across pages.

The bulk action bar appears at the bottom when users are selected, with options to manage secondary emails or change primary emails.
