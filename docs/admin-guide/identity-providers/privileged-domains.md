# Domain Routing

Domain Routing manages your tenant's privileged domains: email domains your organization controls. A privileged domain can route its users to an identity provider and add them to groups automatically.

!!! note "Privileged domains are not protected (web) domains"
    A **privileged domain** is an **email** domain (`acme.com`) used to route users and
    assign groups. A [protected domain](../service-providers/forward-auth.md) is a DNS
    domain proven with a TXT record so WeftID can gate web apps behind it with forward
    auth. The same name can be registered as both, and the two are independent.
    Privileged domains are under **Identity Providers > Domain Routing**. Protected
    domains are under **Applications > Forward Auth > Protected Domains**.

Admins can add and remove domains and link groups. Binding a domain to an identity provider requires a super admin.

## Adding a domain

1. Navigate to **Identity Providers > Domain Routing**
2. Under **Add Privileged Domain**, enter the email domain without the `@` (for example, `acme.com`)
3. Click **Add Domain**

Email addresses on a privileged domain are verified automatically. An admin can add a secondary email address to a user only on a privileged domain.

## Binding an identity provider

Each domain can be bound to one identity provider, either a [SAML IdP](saml-setup.md) or an [OIDC connection](oidc-setup.md). Each domain shows a **Bind to SAML IdP...** and a **Bind to OIDC...** selector. Pick the provider and click **Bind**.

The two kinds of binding behave differently:

* **SAML binding**: every existing user with an address on the domain is assigned to the IdP, and from then on signs in only through it. New users on the domain are routed to the IdP, and created there when the IdP has just-in-time provisioning on. If an assigned user is later removed from the IdP, their account is deactivated and needs an admin to reactivate it.
* **OIDC binding**: only new users are routed. Someone who enters an unrecognized email address on the domain is sent to the connection, which creates their account when it has just-in-time provisioning on. Existing users are not reassigned.

A domain bound to a SAML IdP cannot also be bound to an OIDC connection, and the reverse. Click **Unbind SAML** or **Unbind OIDC** to remove the existing binding first.

Unbinding stops routing new users. Users already assigned to a SAML IdP stay assigned.

## Linking groups

Link one or more groups to a domain. When a user is created with an email address on that domain, they are added to the linked groups automatically. Linking a group also adds existing users on the domain.

This applies to manually created users and just-in-time provisioned users. A user whose address still needs [email confirmation](account-linking.md#confirming-an-unverified-email-address) joins the linked groups once they confirm it.

Unlinking a group keeps existing memberships.

### Example

1. Add the domain `engineering.acme.com`
2. Link it to the "Engineering" group
3. When `alice@engineering.acme.com` is created, she is automatically added to the Engineering group

## Removing a domain

Click **Remove** on the domain. Its identity provider binding and group links are removed with it. Existing users keep their IdP assignment and group memberships.
