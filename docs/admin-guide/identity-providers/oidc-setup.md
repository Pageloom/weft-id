# OIDC Setup

Connect an OpenID Connect identity provider to WeftID. This lets users sign in with credentials from Keycloak, Auth0, Google Workspace, Microsoft Entra ID, or any spec-compliant OIDC provider.

OIDC is a peer to [SAML](saml-setup.md), not a replacement. A tenant can run both at once, and each connection is independent. Choose OIDC when your provider ships it natively or when you would rather exchange a client ID and secret than a signing certificate.

WeftID acts as a relying party here, consuming an upstream provider. That is the opposite direction from [Sign in with WeftID](../integrations/oidc-provider-setup.md), where WeftID is the provider and your own apps are the relying parties.

## How the connection works

WeftID uses the authorization code flow with PKCE, and nothing else. There is no implicit flow and no hybrid flow.

1. A user arrives at the login page and enters their email address, or clicks the connection's **Continue with ...** button if it has one (see [Sign-in page buttons](login-buttons.md)).
2. After an email address, WeftID routes them to the connection, either because they are already linked to it, because their email domain is bound to it, or because it is the tenant default. A user linked to several connections goes to the one they used most recently (see [Account linking](account-linking.md)).
3. WeftID redirects to the provider's authorization endpoint with a `state`, a `nonce`, and a PKCE challenge.
4. The provider authenticates the user and redirects back to WeftID's callback.
5. WeftID exchanges the code for an ID token, verifies its signature against the provider's JWKS, and checks the issuer, audience, nonce, and expiry.
6. WeftID correlates the user, provisions them if this is a first sign-in, and completes the login.

## Step 1: Create the connection

1. Navigate to **Identity Providers > OIDC**
2. Click **Add Connection**
3. Enter a display name
4. Select the provider type (Generic, Google, Entra ID, Microsoft personal accounts, LinkedIn, or GitLab)
5. Click **Create**

Selecting a provider type pre-fills the authority URL, the default scopes, and the correlation claim. Every pre-filled value can be overridden. The vendor walkthroughs cover each preset: [Google Workspace](oidc-google.md), [Microsoft Entra ID](oidc-entra.md), [Microsoft personal accounts](oidc-microsoft.md), [LinkedIn](oidc-linkedin.md), and [GitLab](oidc-gitlab.md).

## Step 2: Register WeftID with your provider

Open the connection's **Details** tab and copy the **redirect URI**. It looks like this:

```
https://<your-tenant>.example.com/auth/oidc/<connection-id>/callback
```

The connection ID is part of the URI, so each connection has its own. Create an application (Keycloak calls it a client, Auth0 an application, Entra an app registration) in your provider's console and register that exact URI as an allowed redirect. A mismatch of even a trailing slash will cause the provider to reject the handshake.

Your provider will then give you a client ID and a client secret.

## Step 3: Enter the credentials

Back in WeftID, edit the connection and supply:

* **Issuer**: the provider's issuer URL, for example `https://auth.example.com/realms/staff`
* **Discovery URL**: usually the issuer plus `/.well-known/openid-configuration`
* **Client ID** and **Client secret**: from your provider

The client secret is encrypted at rest and is never displayed again after you save it. The connection shows only whether a secret is set. To change it, enter a new one.

## Step 4: Test and enable

Click **Test connection**. WeftID fetches the discovery document, checks that its issuer matches the issuer you configured, stores the discovered endpoints, and fetches the signing keys from the document's `jwks_uri`. Failures are reported with the reason. A failed discovery leaves the stored endpoints unchanged. The same test is available through the API:

```
POST /api/v1/oidc-upstream/connections/{connection_id}/test
```

A discovery document is rejected when its `issuer` does not match the configured issuer, or when any of its endpoints is not `https`. Both are signs that something is misconfigured or being intercepted.

Once the test passes, enable the connection.

### Keeping endpoints current

Providers move their endpoints and rotate their signing keys. WeftID refreshes the discovery document at sign-in once the last successful fetch is more than an hour old. Nobody has to click **Test connection** again.

* If the document cannot be retrieved (the provider is unreachable or returns an error), sign-in carries on with the last known endpoints.
* If the document is retrieved but refused (wrong issuer, an endpoint that is not `https`, a redirect, or not a valid document), sign-in stops with a configuration error. It keeps stopping until the provider or the connection is fixed. Each attempt is audited as `oidc_login_failed` with reason `discovery`.

Signing keys are fetched again when an ID token names a key WeftID has not seen, so a key rotation at the provider does not break sign-in.

### What WeftID checks at sign-in

* The ID token must be signed with `RS256` by a key from the provider's key set. A token without a `kid` header is accepted when the key set holds exactly one signing key.
* Its `iss` must equal the configured issuer, its `aud` must include the client ID, and its `nonce` must match the one WeftID sent. `exp`, `iat` and `sub` must be present, and the token must not be expired or issued in the future.
* When the provider has a userinfo endpoint, its response must carry the same `sub` as the ID token, or the sign-in fails (audited as `oidc_login_failed` with reason `userinfo_sub_mismatch`). A userinfo endpoint that is unreachable is tolerated, and the ID token's claims are used.

## Sign-out from the provider

If your provider supports OpenID Connect Back-Channel Logout, WeftID can sign users out when they sign out at the provider. Copy the **Back-Channel Logout URL** from the connection's **Details** tab and register it in the provider's console (Keycloak calls it the backchannel logout URL, Auth0 the back-channel logout URI):

```
https://<your-tenant>.example.com/auth/oidc/<connection-id>/backchannel-logout
```

When the provider ends a session, it sends WeftID a signed logout token. WeftID checks it against the connection's signing keys, issuer and client ID, and signs the user out of every WeftID session that began with that provider session. When the token names only the user, every session the user started through this connection ends. The apps those sessions signed in to are notified by back-channel logout, and their refresh tokens stop working. Each ended session is audited as `user_signed_out` with reason `upstream_backchannel_logout`. A token that fails the checks, or is sent twice, is refused and audited as `oidc_idp_logout_rejected`.

Registering the URL is optional. Without it, signing out at the provider leaves WeftID sessions running until they expire or the user signs out of WeftID.

## Sign-out at the provider

The other direction is optional too. With **Sign Out at the Provider** on (under **Settings** on the **Details** tab), a user who signed in through this connection and then signs out of WeftID is also signed out of the provider, using OpenID Connect RP-Initiated Logout. After the WeftID session ends, the browser goes to the provider's end session endpoint and then back to WeftID's sign-in page.

To set it up:

1. Copy the **Post-Logout Redirect URI** from the **Details** tab and register it in the provider's console as a post-logout (or sign-out) redirect URI:

    ```
    https://<your-tenant>.example.com/logout/complete
    ```

2. Turn on **Sign Out at the Provider** and save.

The provider's end session endpoint comes from its discovery document and is shown on the **Details** tab. If the provider publishes none, the setting has no effect and the tab says so. For a provider without discovery, enter the endpoint by hand (see below). WeftID sends the ID token from the user's sign-in as `id_token_hint`, along with `client_id`, the post-logout redirect URI, and a random `state` that the provider sends back.

The same applies when an app signs a user out through WeftID's own end session endpoint. The browser goes to the provider first and then on to the app's post-logout redirect URI, so the app still gets the user back. If the provider returns without the `state` WeftID sent, or with a different one, WeftID does not forward the browser to the app. It shows its sign-in page instead.

## Providers without discovery

A provider that does not publish `/.well-known/openid-configuration` can still be used by entering its endpoints by hand. This applies to the Generic provider type only. Every other preset publishes discovery, so the manual fields are not shown for them.

* **When creating a connection**, expand **Advanced: manual endpoints** on the form and fill in the authorization endpoint, token endpoint, userinfo endpoint, and JWKS URI. The end session endpoint is optional and only used by **Sign Out at the Provider**.
* **On an existing connection**, open the **Details** tab and click the pencil next to **Endpoints**. A blank field keeps its current value.

Every endpoint must be an `https` URL. The same rule discovery applies to a fetched document applies here.

The endpoints can also be set through the API:

```
PATCH /api/v1/oidc-upstream/connections/{connection_id}
```

Send any of `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, and `end_session_endpoint`.

Entering endpoints by hand stops the hourly refresh at sign-in, so your values stay as entered. They are not protected from **Test connection**, though. If you later click it and the fetch succeeds, the endpoints are replaced with the discovered values and the hourly refresh starts again. For a provider with no discovery document the test fails and your manual values are left as they are.

## Connection settings

* **Enabled**: whether users can sign in through this connection. A disabled connection blocks its linked users from authenticating.
* **Default connection**: new users with no other route are sent here. One connection per tenant can be the default.
* **Show on sign-in page**: put a **Continue with ...** button for this connection on the sign-in page while it is enabled. See [Sign-in page buttons](login-buttons.md).
* **JIT provisioning**: create a WeftID account on first successful sign-in. Without it, only users who already exist and are already linked can sign in.
* **Require two-step verification**: after the provider authenticates the user, WeftID additionally requires its own two-step verification before the session is established. Use this when you do not want to rely solely on the upstream provider's authentication.
* **Allow email linking**: see below.
* **Sign out at the provider**: see [Sign-out at the provider](#sign-out-at-the-provider).
* **Scopes**: space-separated. `openid` is always requested.

### Allow email linking

This setting is off by default, and turning it on has a security consequence worth understanding.

WeftID correlates users by the provider's stable subject claim, recorded per connection. That is what lets someone change their email address upstream without getting a duplicate WeftID account.

The first time a subject appears, WeftID has nothing to match it against. With email linking off, that subject is either provisioned as a new user (if JIT is on) or refused. With email linking on, WeftID will also attach the subject to an **existing** WeftID account when the ID token's email matches and the token asserts `email_verified: true`.

That is convenient when migrating existing users onto a new provider. It also means anyone who can obtain a token from that provider carrying a given verified email can take over the matching WeftID account. Only enable it for a provider you trust to verify email addresses properly, and consider turning it off again once migration is done.

Email linking is unavailable for providers that do not reliably verify email addresses (currently Microsoft personal accounts). It never attaches a second provider account to a user already linked to the same connection, and it never links a user who is assigned to a SAML identity provider. See [Account linking](account-linking.md) for the full policy.

## Claim mapping

The **Claim mapping** tab maps claims from the provider onto WeftID's standard user attributes. The default mapping is:

| WeftID attribute | OIDC claim |
|------------------|-----------|
| Email | `email` |
| First name | `given_name` |
| Last name | `family_name` |

Mapped values are mirrored into the user's profile on every sign-in, subject to the tenant's attribute settings: a value is written to the canonical profile field only where that attribute is enabled and set to mirror from the IdP. Claims that map to unknown attributes are ignored.

Mirroring is best-effort. A mapping problem will not prevent a user from signing in.

## Group claims

The **Claim mapping** tab also holds the connection's group claim settings. Leave the claim name empty (the default) and WeftID never touches group membership for this connection. Set it, and every sign-in through the connection syncs the user's groups from that claim.

How it works:

* **Base group.** Every connection has a base group with the connection's name. Every user who signs in through the connection is added to it, whether or not a group claim is configured. The base group is created with the connection, renamed with it, and deleted with it.
* **Discovered groups.** Each value in the claim becomes an IdP-type group under the base group, created the first time it is seen. Membership is read-only in WeftID and is updated on every sign-in: the user is added to the groups in the claim and removed from this connection's groups that are no longer listed.
* **Absent claim.** If the token carries no such claim at all, memberships are left as they are. A missing claim usually means a scope or provider setting rather than "no groups", so WeftID does not strip access on it. An explicitly empty list does remove the user from all of the connection's discovered groups.

WeftID reads the claim from the ID token, and from the userinfo response when the token does not carry it. Accepted shapes:

* a list of names: `["engineering", "ops"]`
* a list of objects, with the group name under the configured **name key** (default `name`): `[{"id": "…", "name": "engineering"}]`
* a single name as a string

Names are trimmed and de-duplicated. Values longer than 200 characters are ignored.

Groups synced this way behave exactly like groups synced from a SAML assertion: they appear under **Groups** with the connection's name as their source, can be used for [group-based access](../groups/group-based-access.md), and cannot be edited by hand.

Provider notes:

* **Okta**: add a `groups` claim to the authorization server (**Security > API > Authorization Servers > Claims**), include it in the ID token, and use the claim's group filter to limit which groups are released. Add `groups` to the connection's scopes if the claim is scoped to it.
* **Microsoft Entra ID**: enable the groups claim on the app registration. The claim carries group object IDs, not names, so synced groups are named by GUID. See [OIDC with Microsoft Entra ID](oidc-entra.md#groups).
* **Google Workspace**: no groups claim is available over OIDC.
* **GitLab**: the `groups` claim carries group paths. See [OIDC with GitLab](oidc-gitlab.md#groups).
* **Microsoft personal accounts and LinkedIn**: no groups claim.
* **Keycloak, Auth0, Authentik and other generic providers**: add a mapper or action that puts the user's groups into a claim, then enter that claim's name here. Namespaced names such as `https://example.com/groups` work.

## Correlation claim

Most providers use `sub` as the stable subject. Entra is the exception: its `sub` is unique per application, so the Entra preset correlates on `oid` instead, per Microsoft's guidance. Personal Microsoft accounts carry no `oid`, so that preset uses `sub`.

Changing the correlation claim on a connection that already has linked users will orphan those links, and affected users will be treated as new subjects on their next sign-in. Change it before the connection goes into use, not after.

## Disconnecting a user

The **Danger** tab lists users linked to the connection and can unlink them individually. A user's own **Profile** tab lists all of their links, across connections, with the same action. Unlinking removes the subject link and scrubs mirrored attribute values that still match what the provider supplied, leaving anything the user set themselves. The account itself is not deleted. If it was the user's last link, the account is deactivated (see [Account linking](account-linking.md#viewing-and-removing-links)).

## Deleting a connection

Deleting a connection removes its user links, mirrored attributes, and the groups synced from it (including the base group). Users who could only sign in through that connection will no longer have a way in, so give them a password or another connection first.

A connection bound to a [privileged domain](privileged-domains.md) cannot be deleted until the binding is removed.
