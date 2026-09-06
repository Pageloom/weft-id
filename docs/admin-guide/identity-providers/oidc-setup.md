# OIDC Setup

Connect an OpenID Connect identity provider to WeftID. This lets users sign in with credentials from Keycloak, Auth0, Google Workspace, Microsoft Entra ID, or any spec-compliant OIDC provider.

OIDC is a peer to [SAML](saml-setup.md), not a replacement. A tenant can run both at once, and each connection is independent. Choose OIDC when your provider ships it natively or when you would rather exchange a client ID and secret than a signing certificate.

WeftID acts as a relying party here, consuming an upstream provider. That is the opposite direction from [Sign in with WeftID](../integrations/oidc-provider-setup.md), where WeftID is the provider and your own apps are the relying parties.

## How the connection works

WeftID uses the authorization code flow with PKCE, and nothing else. There is no implicit flow and no hybrid flow.

1. A user arrives at the login page and enters their email address.
2. WeftID routes them to the connection, either because they are already linked to it, because their email domain is bound to it, or because it is the tenant default.
3. WeftID redirects to the provider's authorization endpoint with a `state`, a `nonce`, and a PKCE challenge.
4. The provider authenticates the user and redirects back to WeftID's callback.
5. WeftID exchanges the code for an ID token, verifies its signature against the provider's JWKS, and checks the issuer, audience, nonce, and expiry.
6. WeftID correlates the user, provisions them if this is a first sign-in, and completes the login.

## Step 1: Create the connection

1. Navigate to **Identity Providers > OIDC**
2. Click **Add Connection**
3. Enter a display name
4. Select the provider type (Generic, Google, or Entra)
5. Click **Create**

Selecting a provider type pre-fills the authority URL, the default scopes, and the correlation claim. Every pre-filled value can be overridden. See [Google Workspace](oidc-google.md) and [Microsoft Entra ID](oidc-entra.md) for the vendor walkthroughs.

## Step 2: Register WeftID with your provider

Open the connection's **Details** tab and copy the **redirect URI**. It looks like this:

```
https://<your-tenant>.example.com/auth/oidc/<connection-id>/callback
```

The connection ID is part of the URI, so each connection has its own. Create an application (Keycloak calls it a client, Auth0 an application, Entra an app registration) in your provider's console and register that exact URI as an allowed redirect. A mismatch of even a trailing slash will cause the provider to reject the handshake.

Your provider will then give you a client ID and a client secret.

## Step 3: Enter the credentials

Back in WeftID, edit the connection and supply:

* **Issuer** — the provider's issuer URL, for example `https://auth.example.com/realms/staff`
* **Discovery URL** — usually the issuer plus `/.well-known/openid-configuration`
* **Client ID** and **Client secret** — from your provider

The client secret is encrypted at rest and is never displayed again after you save it. The connection shows only whether a secret is set. To change it, enter a new one.

## Step 4: Test and enable

Click **Test connection**. WeftID fetches the discovery document, checks that its issuer matches the issuer you configured, and stores the discovered endpoints. Failures are reported with the reason and the connection is left unchanged.

A discovery document is rejected when its `issuer` does not match the configured issuer, or when any of its endpoints is not `https`. Both are signs that something is misconfigured or being intercepted.

Once the test passes, enable the connection.

## Providers without discovery

A provider that does not publish `/.well-known/openid-configuration` can still be used by entering its endpoints by hand. This applies to the Generic provider type only. Google and Entra always publish discovery, so the manual fields are not shown for them.

* **When creating a connection**, expand **Advanced: manual endpoints** on the form and fill in the authorization endpoint, token endpoint, userinfo endpoint, and JWKS URI.
* **On an existing connection**, open the **Details** tab and click the pencil next to **Endpoints**. A blank field keeps its current value.

Every endpoint must be an `https` URL. The same rule discovery applies to a fetched document applies here.

The endpoints can also be set through the API:

```
PATCH /api/v1/oidc-upstream/connections/{connection_id}
```

Send any of `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, and `jwks_uri`.

Manual values are not protected from discovery. If you later click **Test connection** and the fetch succeeds, all four endpoints are replaced with the discovered values. For a provider with no discovery document the test fails and your manual values are left as they are.

## Connection settings

* **Enabled** — whether users can sign in through this connection. A disabled connection blocks its linked users from authenticating.
* **Default connection** — new users with no other route are sent here. One connection per tenant can be the default.
* **JIT provisioning** — create a WeftID account on first successful sign-in. Without it, only users who already exist and are already linked can sign in.
* **Require two-step verification** — after the provider authenticates the user, WeftID additionally requires its own two-step verification before the session is established. Use this when you do not want to rely solely on the upstream provider's authentication.
* **Allow email linking** — see below.
* **Scopes** — space-separated. `openid` is always requested.

### Allow email linking

This setting is off by default, and turning it on has a security consequence worth understanding.

WeftID correlates users by the provider's stable subject claim, recorded per connection. That is what lets someone change their email address upstream without getting a duplicate WeftID account.

The first time a subject appears, WeftID has nothing to match it against. With email linking off, that subject is either provisioned as a new user (if JIT is on) or refused. With email linking on, WeftID will also attach the subject to an **existing** WeftID account when the ID token's email matches and the token asserts `email_verified: true`.

That is convenient when migrating existing users onto a new provider. It also means anyone who can obtain a token from that provider carrying a given verified email can take over the matching WeftID account. Only enable it for a provider you trust to verify email addresses properly, and consider turning it off again once migration is done.

## Claim mapping

The **Claim mapping** tab maps claims from the provider onto WeftID's standard user attributes. The default mapping is:

| WeftID attribute | OIDC claim |
|------------------|-----------|
| Email | `email` |
| First name | `given_name` |
| Last name | `family_name` |

Mapped values are mirrored into the user's profile on every sign-in, subject to the tenant's attribute settings: a value is written to the canonical profile field only where that attribute is enabled and set to mirror from the IdP. Claims that map to unknown attributes are ignored.

Mirroring is best-effort. A mapping problem will not prevent a user from signing in.

## Correlation claim

Most providers use `sub` as the stable subject. Entra is the exception: its `sub` is unique per application, so the Entra preset correlates on `oid` instead, per Microsoft's guidance.

Changing the correlation claim on a connection that already has linked users will orphan those links, and affected users will be treated as new subjects on their next sign-in. Change it before the connection goes into use, not after.

## Disconnecting a user

The **Danger** tab lists users linked to the connection and can unlink them individually. Unlinking removes the subject link and scrubs mirrored attribute values that still match what the provider supplied, leaving anything the user set themselves. The account itself is not deleted.

## Deleting a connection

Deleting a connection removes its user links and mirrored attributes. Users who could only sign in through that connection will no longer have a way in, so give them a password or another connection first.

A connection bound to a [privileged domain](privileged-domains.md) cannot be deleted until the binding is removed.
