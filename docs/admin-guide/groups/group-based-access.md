# Group-Based Access

Groups control which users can access which applications. The same model applies to SAML service providers, OIDC-enabled apps, and forward-auth apps.

## How it works

Each application is either **Available to all** or restricted to assigned groups. For a restricted application, WeftID checks at sign-in whether the user belongs to an assigned group, directly or through a descendant group. If not, access is denied and the attempt is logged.

Plain OAuth2 apps (OIDC disabled) are not gated by groups.

## Assigning groups

- **SAML service provider**: Open the SP and select the **Groups** tab. Choose a group and click **Assign**.
- **OIDC app**: Open the app under **Applications > OAuth2 / OIDC**. Under **Access Mode**, switch to group-based access, then assign groups.
- **Forward-auth app**: Open the app under **Applications > Forward Auth > Proxy Apps**. Under **Group Grants**, choose a group to grant.

Repeat to assign more groups. A user needs to be in at least one of them.

From a group's **Applications** tab you can also assign an application to the group and see what it inherits from its parents.

## Access and the hierarchy

An assignment grants access to the group's members and to the members of every descendant group. Assigning an application to a parent group grants a whole branch at once.

The reverse does not hold. A member of a parent group gets nothing assigned only to its children.

To see everything a user can reach and why, open the user's **Apps** tab.

## Groups in assertions

When an SP has [group claims](../service-providers/attribute-mapping.md#group-claims) enabled, the assertion includes the user's group memberships. How many groups are included depends on the [group assertion scope](../service-providers/attribute-mapping.md#group-assertion-scope) setting.

With the default scope ("access-granting groups only"), only the groups that grant the user access to the specific SP are shared. This minimizes the information disclosed to each application. The scope can be widened to top-level groups or all groups at the tenant level or per SP.
