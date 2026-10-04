# Account Linking

A WeftID account can be linked to accounts at several OIDC providers. Someone might sign in with Google on Monday and GitLab on Tuesday, and land in the same WeftID account both times. This page explains how those links are made, how WeftID chooses between them, and what it refuses.

Links apply to [OIDC connections](oidc-setup.md). SAML works differently: a user is assigned to one SAML identity provider, and that assignment always wins (see [SAML-assigned users](#saml-assigned-users)).

## What a link is

A link ties one account at a provider (its stable subject, usually the `sub` claim) to one WeftID user. The rules:

* A user can be linked to any number of OIDC connections.
* A user has at most one link per connection. Two GitHub accounts cannot both sign in to the same WeftID account through the same GitHub connection.
* An account at a provider is linked to at most one WeftID user.

## How links are made

A link is created the first time an account at a provider signs in to WeftID, in one of two ways:

* **Just-in-time provisioning.** The connection has JIT provisioning on and no WeftID account uses the email address yet. WeftID creates the account and links it.
* **Email linking.** The connection has **Allow email linking** on, the provider says the email address is verified, and a WeftID account with that email already exists. WeftID links the provider account to the existing WeftID account.

Email linking is how a user who already has a WeftID account adds a second provider: they sign in with the new provider, and the verified email address matches their account.

If the user is already linked to that connection under a different provider account, email linking refuses the sign-in instead of adding a second link. The login page tells the user to sign in with the account they linked before. An administrator can unlink the old account first if the change is intended.

## Which providers can link by email

Email linking trusts the provider's statement that the user controls the email address. Some providers do not make that statement reliably, so WeftID never links by email on them, whatever the connection's setting:

* **Microsoft personal accounts**: tokens carry no `email_verified` claim, and the account's email address does not have to be one the user controls.

For these providers the **Allow email linking** setting is unavailable in the admin UI, and the API rejects it. Users of these providers get a new account through JIT provisioning, or are refused.

Every other provider links only when its token says `email_verified: true`. See [Allow email linking](oidc-setup.md#allow-email-linking) for the security trade-off before turning it on.

## Signing in with an email address

When a linked user enters their email address on the login page, WeftID sends them to the connection they used most recently. If that connection is disabled, WeftID tries the next most recent one. A user whose every linked connection is disabled is told that their identity provider is disabled.

A user with links never needs to remember which provider to choose. Signing in through any linked connection works, and that connection becomes the one email sign-in uses next time.

## SAML-assigned users

A user assigned to a SAML identity provider signs in through that provider only. If they arrive through an OIDC connection, WeftID refuses the sign-in and sends them back to the login page to sign in with their email address. This holds even if the user has OIDC links from before the SAML assignment, so an OIDC provider can never be used to get around an organization's SAML policy.

Each refusal is recorded in the event log as **OIDC upstream sign-in refused by the account-linking policy**, with the reason.

## Viewing and removing links

Super admins see a user's links on the user's **Profile** tab, under **Authentication Method > Linked sign-in accounts**. The list shows each connection, the provider account's subject, when the link was made, and when it was last used.

**Unlink** removes one link and clears the attribute values that still match what that provider supplied. What happens to the account depends on what is left:

* **Other links remain**: the user keeps signing in through them. Nothing else changes.
* **It was the last link**: the account is also deactivated, its email addresses are marked unverified, and its tokens are revoked. This mirrors disconnecting a user from a SAML identity provider. Give the user a password or another connection before reactivating them.

The same list and action are available from the connection's **Danger** tab (all users of one connection) and through the API:

* `GET /api/v1/users/{user_id}/oidc-links` lists a user's links.
* `DELETE /api/v1/users/{user_id}/oidc-links/{connection_id}` unlinks one.
