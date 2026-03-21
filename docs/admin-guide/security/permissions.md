# Permissions

Control what users can do in their own accounts. Super admins are exempt from these restrictions.

Navigate to **Settings > Security > Permissions**.

## Allow users to edit their profile

When enabled, users can change their own name on the profile page. When disabled, only admins can update user names.

## Allow users to add email addresses

When enabled, users can add and verify additional email addresses on their account. When disabled, only admins can manage user email addresses.

## Group assertion scope

Controls which group memberships are shared with service providers during SAML sign-in. This setting is the tenant-wide default. Each SP can override it on its **Attributes** tab.

| Scope | What's shared |
|-------|--------------|
| **Access-granting groups only** (default) | Only the groups that grant the user access to the SP. For SPs available to everyone, top-level groups are shared instead. |
| **Top-level groups only** | The user's highest-level group memberships, without enumerating nested groups. |
| **All groups** | All of the user's group memberships, including nested and inherited groups. |

If group claims are disabled on a specific SP, no groups are shared regardless of this setting.

For details on how scope affects assertions, see [Group claims](../service-providers/attribute-mapping.md#group-claims). Changes to this setting are recorded in the [audit log](../audit/index.md).
