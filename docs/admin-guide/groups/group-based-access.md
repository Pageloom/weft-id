# Group-Based Access

Groups control which users can access which service providers.

## How it works

Each service provider can be restricted to specific groups. During SSO, WeftID checks whether the user belongs to any assigned group, or to a descendant of one. If not, access is denied.

If a service provider is set to **Available to all**, group assignments are bypassed and all active users can access it.

## Assigning groups to a service provider

1. Go to the service provider's detail page
2. Open the **Groups** tab
3. Click **Assign Groups**
4. Select one or more groups
5. Click **Assign**

Multiple groups can be assigned to one SP. A user needs to be in at least one of them.

## Viewing assignments from a group

From a group's detail page, you can see which service providers are assigned to that group.

## Access and the hierarchy

Access assignments apply to the assigned group and every group beneath it. When a service provider is assigned to a group, its members can access the SP, and so can the members of any descendant group, resolved through the [group hierarchy](group-hierarchy.md). Assigning an SP to a parent group is the way to grant a whole branch at once.

Membership itself does not flow downward: a user in a child group is not automatically a member of the parent. It is the access grant that flows down the hierarchy, not the membership.

## Groups in assertions

When an SP has [group claims](../service-providers/attribute-mapping.md#group-claims) enabled, the assertion includes the user's group memberships. How many groups are included depends on the [group assertion scope](../service-providers/attribute-mapping.md#group-assertion-scope) setting.

With the default scope ("access-granting groups only"), only the groups that grant the user access to the specific SP are shared. This minimizes the information disclosed to each application. The scope can be widened to top-level groups or all groups at the tenant level or per SP.
