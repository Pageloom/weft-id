# Sign in with WeftID (OIDC)

WeftID can act as an **OpenID Provider (OP)** so downstream applications can offer a "Sign in with WeftID" button and receive verifiable identity claims. OIDC is layered on top of the [Apps](apps.md) authorization code flow: an OIDC-enabled app receives a signed ID token in addition to the OAuth2 access and refresh tokens.

This page covers registering a downstream app as an OIDC relying party. For the OAuth2 mechanics (authorization code flow, PKCE, token lifetimes), see [Apps](apps.md).

## Enabling OIDC on an app

1. Create an app under **Applications > OAuth2 / OIDC** (or open an existing one).
2. On the app's detail page, find the **OpenID Connect** section and click **Enable OIDC**.

Enabling OIDC changes two behaviors:

* The token endpoint issues a signed RS256 **ID token** whenever the request includes the `openid` scope.
* **Group-based access control** is enforced at sign-in. A user who is not granted access is denied at the authorize step (they never receive a code or token).

Plain OAuth2 apps (OIDC disabled) are unaffected by both changes.

## Discovery URL and endpoints

Once OIDC is enabled, the app detail page shows the read-only **endpoint URLs** for your tenant. Copy these into your downstream application. Most OIDC client libraries need only the discovery URL and will fetch the rest automatically.

* **Issuer**: `https://<your-tenant-host>`
* **Discovery URL**: `https://<your-tenant-host>/.well-known/openid-configuration`
* **JWKS URI**: `https://<your-tenant-host>/.well-known/jwks.json` (public keys for verifying ID token signatures)
* **Authorization endpoint**: `https://<your-tenant-host>/oauth2/authorize`
* **Token endpoint**: `https://<your-tenant-host>/oauth2/token`
* **UserInfo endpoint**: `https://<your-tenant-host>/userinfo`
* **End session endpoint**: `https://<your-tenant-host>/oauth2/logout` (see [Signing out](#signing-out))
* **Introspection endpoint**: `https://<your-tenant-host>/oauth2/introspect` (see [Token Introspection and Revocation](token-introspection.md))
* **Revocation endpoint**: `https://<your-tenant-host>/oauth2/revoke`
* **Device authorization endpoint**: `https://<your-tenant-host>/oauth2/device_authorization` (see [Device Sign-In](device-sign-in.md))
* **Pushed authorization request endpoint**: `https://<your-tenant-host>/oauth2/par` (see [Pushed authorization requests](#pushed-authorization-requests))

The issuer and every endpoint are scoped to your tenant host. A relying party configured against one tenant's issuer can never receive another tenant's keys or claims.

## Redirect URIs

OIDC uses the same **Redirect URIs** as the app's OAuth2 configuration. Add each callback URL (one per line, exact match, no wildcards) in the app's edit form. After a successful sign-in, WeftID redirects the browser to one of these URIs with the authorization code.

## Launching from My Apps

An OIDC app can appear in users' **My Apps** list on the dashboard, like a SAML application. Set the app's **Login initiation URI** on its edit form: the address in the app that starts a sign-in with WeftID. This is OpenID Connect third-party-initiated login.

* The URI must be an absolute `https` URL without a fragment. It may have a query.
* The app appears in My Apps for every user who can access it (see [Controlling who can sign in](#controlling-who-can-sign-in)), as long as OIDC is turned on for the app and the app is active.
* When a user opens it, their browser goes to the login initiation URI with one added parameter, `iss`: WeftID's issuer for your tenant, as in the discovery document. The app should check that `iss` is the issuer it trusts and then send the user to the authorization endpoint as it normally would. The user is already signed in to WeftID, so the round trip is usually seamless.
* WeftID sends no `login_hint` and no `target_link_uri`. The app lands the user wherever it normally does after sign-in.

Through the API, set `initiate_login_uri` with `POST` or `PATCH /api/v1/oauth2/clients/{client_id}` (an empty string clears it). An app that registers itself can send `initiate_login_uri` in its registration (see [Client Registration](client-registration.md)).

## Asking the user to sign in again

An app can make a user who is already signed in to WeftID sign in again:

* `prompt=login` (or `prompt=select_account`) on the authorization request.
* `max_age`, when the user's sign-in is older than that many seconds.
* An `id_token_hint` that names a different user than the one signed in.

WeftID first shows a **Sign in again?** page naming the app. This stops a link on another website from signing the user out. If the user continues, WeftID ends their current session and they sign in to WeftID again (password, then two-step verification per policy). The authorization request then carries on as usual. If they cancel, the app receives `access_denied`. With `prompt=none`, WeftID shows no page and answers `login_required` instead.

Ending the session this way triggers [front-channel](#front-channel-logout) and [back-channel](#back-channel-logout) logout for the user's other apps, but not for the app that asked. The new sign-in happens in WeftID only. It is not passed on to the upstream identity provider the user originally signed in with.

## Signing out

An app can sign the user out of WeftID by sending the browser to the **end session endpoint** (OpenID Connect RP-Initiated Logout). Most OIDC client libraries do this for you once they know the discovery URL.

The endpoint accepts `GET` and `POST` with these parameters:

* `id_token_hint`: an ID token WeftID issued to your app for this user (an expired one is fine). Strongly recommended.
* `post_logout_redirect_uri`: where to send the user afterwards. Must exactly match one of the app's **Post-logout redirect URIs**.
* `state`: any value; it is passed back to the `post_logout_redirect_uri`.
* `client_id`: optional; must match the `id_token_hint` when both are sent.

What happens:

* With a valid `id_token_hint` for the signed-in user, WeftID signs the user out straight away. The browser then goes to the `post_logout_redirect_uri` (with `state`), or to a "You have signed out" page when none was sent.
* In every other case (no hint, a hint WeftID cannot verify or that names a different user, or a `post_logout_redirect_uri` that is not registered) WeftID asks the user to confirm. After they confirm, they see the "You have signed out" page. WeftID never sends the user to an address it could not verify.

Signing out through the end session endpoint also ends the user's sessions at SAML applications WeftID signed them in to. It can also sign them out of the upstream identity provider (such as Okta or Entra ID) they used to sign in to WeftID: a SAML identity provider with an SLO URL (see [Single Logout](../identity-providers/saml-setup.md#single-logout)), or an OIDC connection with **Sign Out at the Provider** on (see [Sign-out at the provider](../identity-providers/oidc-setup.md#sign-out-at-the-provider)). The browser goes to the provider first and then on to the app's post-logout redirect URI. Remembered consent is not affected: signing out ends the session, not the user's decision to allow the app.

### Post-logout redirect URIs

Add each address your app may return to after sign-out in the **Post-logout redirect URIs** box on the app's edit form, one per line. Each must be an absolute `http` or `https` URL without a fragment, and WeftID compares them exactly. Leave the box empty if your app does not need to be sent back. Through the API, set `post_logout_redirect_uris` with `PATCH /api/v1/oauth2/clients/{client_id}`.

### Front-channel logout

An app can also ask to be told when the user's WeftID session ends, however it ends: through the end session endpoint, the WeftID sign-out button, or WeftID asking the user to sign in again (`prompt=login` or an expired `max_age`). This is OpenID Connect Front-Channel Logout. Set the app's **Front-channel logout URI** on its edit form. When the session ends, WeftID shows a short "Signing you out" page that loads that URI in a hidden frame for every app that received an ID token during the session, and then continues on its way.

* The URI must be an absolute `http` or `https` URL without a fragment, on the same scheme, host and port as one of the app's redirect URIs. It may have a query.
* By default WeftID adds `iss` and `sid` to the request (**Send the issuer and session ID**, on for new apps). The `sid` matches the `sid` claim in the ID tokens the app received, so the app can find the session to end. Browsers that block third-party cookies do not send the app's own cookies to a hidden frame, so most apps need these parameters. Untick the box only if the app requires a bare request.
* The app's page should end its local session and return quickly. WeftID moves on once every frame has loaded, or after five seconds at most.
* When WeftID asks the user to sign in again for an app, that app is not sent a front-channel logout: it is in the middle of signing the user in.

Through the API, set `frontchannel_logout_uri` and `frontchannel_logout_session_required` with `POST` or `PATCH /api/v1/oauth2/clients/{client_id}`.

### Back-channel logout

Front-channel logout depends on the user's browser. Back-channel logout does not: when the session ends (the same three ways), WeftID sends a signed logout token straight to the app's server. This is OpenID Connect Back-Channel Logout. Set the app's **Back-channel logout URI** on its edit form.

* The URI must be an absolute `http` or `https` URL without a fragment. Unlike the front-channel URI it may be on any host, for example an internal API. WeftID refuses to call private or reserved network addresses.
* WeftID `POST`s a form with one field, `logout_token`: a JWT signed with the same key as the ID tokens (check it against the JWKS). It carries `iss`, `aud` (the app's client ID), `iat`, `exp`, `jti`, `events`, `sub`, and `sid` unless you untick **Include the session ID** (on for new apps). It never carries a `nonce`.
* The app should end the matching session and answer `200`. Any other `2xx` also counts as delivered. A `4xx` (other than `408` and `429`) tells WeftID the app rejected the token, and it does not try again.
* Delivery happens in the background, usually within ten seconds. If the app cannot be reached or answers with a `5xx`, WeftID retries after 30 seconds, 2 minutes, 10 minutes, 1 hour and 6 hours. A delivery that is given up is recorded in the audit log as `oidc_backchannel_logout_failed`.
* As with front-channel logout, the app that asked WeftID to sign the user in again is not sent a logout token.
* Deactivating, anonymizing or deleting a user also sends a logout token for each session the user holds with the app, whoever or whatever deactivated them (an admin, SCIM, the inactivity policy, or removal from an identity provider). No browser is involved, so front-channel logout does not apply here.

The app's detail page lists the most recent deliveries under **Back-Channel Logout Deliveries**: who they were for, whether they were delivered, how many attempts were made, and the last error. "Address not allowed or not found" means the URI's host did not resolve, or resolved to an address WeftID refuses to call. Deliveries are kept for 30 days after they finish.

Through the API, set `backchannel_logout_uri` and `backchannel_logout_session_required` with `POST` or `PATCH /api/v1/oauth2/clients/{client_id}`, and list deliveries with `GET /api/v1/oauth2/clients/{client_id}/backchannel-logout-deliveries` (`status`, `page` and `limit` query parameters).

### Refresh tokens end with the session

A refresh token issued together with an ID token belongs to the WeftID session the user signed in with. When that session ends (any of the three ways above), WeftID revokes it, along with the access tokens minted from it. The app must send the user through sign-in again to get new tokens. Refresh tokens issued without the `openid` scope are not tied to a session and are unaffected. Deactivating a user revokes all of their tokens, as before.

## Scopes and claims

WeftID gates released claims by the scopes a relying party **requests** at authorize time. There is no per-app scope allowlist to configure: request the scopes your app needs, and WeftID releases only the matching claims.

Supported scopes and the claims they release:

* `openid`: required for an ID token. Releases the envelope claims: `sub` (the stable WeftID user id, never the email, or a [pairwise identifier](pairwise-subjects.md) for an app set to pairwise), `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce` (when supplied), and `sid` (the WeftID session the user signed in with).
* `profile`: `name`, `given_name`, `family_name`, `locale`, `zoneinfo`, `updated_at`. Claims WeftID has no data for (such as `nickname`, `picture`, or `birthdate`) are left out, never sent empty.
* `email`: `email`, `email_verified`.
* `groups`: `groups`, the user's effective group memberships (see below).

The ID token carries only the `openid` envelope claims. The `profile`, `email`, and `groups` claims come from the **UserInfo endpoint**, called with the access token from the same token response. This follows OpenID Connect Core section 5.4 for the authorization code flow, and it keeps personal data out of a token that the app may pass on to other parties. Most OIDC client libraries call UserInfo automatically after sign-in.

The UserInfo endpoint accepts `GET` and `POST`. Send the access token in the `Authorization: Bearer` header, or, with `POST`, as the `access_token` form field (not both). The token must have been issued to an OIDC-enabled app.

## Group-claim behavior

When the `groups` scope is granted, the UserInfo response includes a `groups` claim listing the user's **effective** group names. Effective membership is DAG-aware: it includes groups the user belongs to directly plus all ancestor groups reachable through the group hierarchy. The claim is always present (as an empty list when the user has no groups) whenever the scope is granted, so relying parties can treat "no `groups` claim" and "empty `groups`" unambiguously.

## Controlling who can sign in

OIDC-enabled apps enforce access control at sign-in, mirroring the [SAML service provider](../service-providers/index.md) model:

* **Group-based access** (default): Only members of assigned groups, and members of their descendant groups, can sign in. Assign groups in the **Assigned Groups** panel on the app detail page.
* **Available to all users**: Every active tenant user can sign in. Toggle this in the **Access Mode** panel. Group assignments remain visible but are organizational only.

A denied user sees an access-denied error instead of the consent screen and is never issued a code or token. Denials are recorded in the audit log.

## Managing OIDC via the API

Everything above is available through the REST API under `/api/v1/oauth2/clients/{client_id}`:

* `PATCH /{client_id}/oidc`: toggle `oidc_enabled` and/or `available_to_all`.
* `GET /{client_id}/oidc/urls`: fetch the discovery/JWKS/endpoint URLs.
* `GET /{client_id}/groups`: list assigned groups.
* `POST /{client_id}/groups`: assign a group (`{"group_id": "..."}`).
* `POST /{client_id}/groups/bulk`: assign several groups (`{"group_ids": [...]}`).
* `DELETE /{client_id}/groups/{group_id}`: remove a group assignment.
* `GET /{client_id}/backchannel-logout-deliveries`: list back-channel logout deliveries, newest first.

Redirect URIs, post-logout redirect URIs, and front- and back-channel logout are managed through the existing `PATCH /{client_id}` endpoint (`redirect_uris`, `post_logout_redirect_uris`, `frontchannel_logout_uri`, `frontchannel_logout_session_required`, `backchannel_logout_uri`, `backchannel_logout_session_required`).

## Signing key rotation

WeftID signs ID tokens with a per-tenant RSA key, published at the JWKS URI. The key is provisioned automatically the first time it is needed; no setup is required. Operators can inspect and rotate it under `/api/v1/oidc/signing-key`:

* `GET /api/v1/oidc/signing-key`: current key metadata: `kid`, `algorithm`, `created_at`, plus the retired key's `previous_kid` and `rotation_grace_period_ends_at` while a rotation is in its grace window. Admin role required. No key material is ever returned.
* `POST /api/v1/oidc/signing-key/rotate`: generate a new signing key. Optional body `{"grace_period_hours": 24}` (1 to 720) controls how long the retired key stays published in the JWKS so relying parties can still verify in-flight ID tokens. Rotation is refused while a prior rotation is still within its grace period. Super admin role required.
* `POST /api/v1/oidc/signing-key/cleanup`: remove the retired key immediately after its grace period has ended, without waiting for the automatic sweep. A key still within its grace window is never removed. Super admin role required.

New tokens are signed with the new key as soon as the rotation completes. Relying parties that fetch keys from the JWKS URI (the normal case) pick up the change automatically. A background sweep removes retired keys once their grace period lapses; rotations and cleanups are recorded in the audit log.

## Request objects and signed UserInfo

An app can send its authorization request parameters inside a signed JWT, a **request object** (OpenID Connect Core section 6), instead of in the URL:

* **By value**: the `request` parameter holds the JWT.
* **By reference**: the `request_uri` parameter holds an `https` URL where WeftID fetches the JWT. The URL must be one the app registered in `request_uris` through [client registration](client-registration.md). A fragment on the URL is ignored when matching.

The request object must be signed with `RS256`, `PS256`, or `ES256` by one of the app's public keys (set under **Client Authentication** on the app page, or registered as `jwks` / `jwks_uri`). Unsigned request objects are refused. When the object carries `iss` it must be the app's client ID, and when it carries `aud` it must include the tenant issuer. Values in the object replace the same parameters in the URL. `client_id` and `response_type` must match when both are present. A request object that cannot be used is answered with `invalid_request_object` or `invalid_request_uri`.

An app registered with `userinfo_signed_response_alg` set to `RS256` gets UserInfo responses as a JWT (`application/jwt`), signed with the tenant's OIDC signing key and carrying `iss` and `aud`.

## Pushed authorization requests

With pushed authorization requests (PAR, RFC 9126), an app sends its authorization request to WeftID server to server before it sends the user's browser anywhere. The parameters never pass through the browser, so they can't be read or changed there.

1. The app posts the authorization parameters (`redirect_uri`, `response_type`, `scope`, `state`, `nonce`, PKCE, and so on, or a signed `request` object) to `POST /oauth2/par`, authenticating the same way as at the token endpoint: client secret (Basic or form) or [private key JWT](private-key-jwt.md).
2. WeftID checks the parameters as the authorization endpoint would and answers `201` with a `request_uri` (`urn:ietf:params:oauth:request_uri:...`) and `expires_in` (60 seconds). A bad parameter gets a JSON error (`400`) right away, instead of a redirect later.
3. The app sends the browser to `/oauth2/authorize?client_id=...&request_uri=...`. Any other parameter on that URL is ignored.

A `request_uri` works once, only for the app that pushed it, and only until it expires. If the user has to sign in first, the request waits for them, still without its parameters in the URL. Only confidential apps can push requests, and only apps that use the authorization code flow.

To make an app use PAR for every sign-in, turn on **Require pushed authorization requests** on the app's edit form, set `require_pushed_authorization_requests` with `PATCH /api/v1/oauth2/clients/{client_id}`, or register the app with it (see [client registration](client-registration.md)). WeftID then refuses that app's authorization requests unless they come with a pushed `request_uri`. Discovery publishes the endpoint as `pushed_authorization_request_endpoint`.

## Access requirements

Admin or super admin role required to manage OIDC settings and group assignments. Signing-key rotation and cleanup require the super admin role.

## What is not supported

WeftID implements the functional OpenID Provider surface: discovery, JWKS, RS256 ID tokens, UserInfo, scope-gated claims, nonce binding, `prompt`, `max_age`, `login_hint`, `id_token_hint`, the `query` and `form_post` response modes, RP-initiated, front-channel and back-channel logout, token introspection and revocation, [private key JWT](private-key-jwt.md) client authentication, [client registration](client-registration.md), [third-party-initiated login](#launching-from-my-apps), [device sign-in](device-sign-in.md), [request objects](#request-objects-and-signed-userinfo), [pushed authorization requests](#pushed-authorization-requests), [pairwise subject identifiers](pairwise-subjects.md), and group-based access control.

These parts of the specification are not supported, and discovery says so:

* **Unsigned or encrypted request objects.** Request objects must be signed (see [Request objects and signed UserInfo](#request-objects-and-signed-userinfo)).
* **The `claims` request parameter** is ignored (`claims_parameter_supported` is `false`). Claims are released by scope only.
* **No `acr` claim.** WeftID defines no authentication context classes, so `acr_values` is accepted but has no effect.
* **Response types other than `code`** (implicit and hybrid flows).
* **Mutual TLS and `client_secret_jwt` client authentication.** Clients authenticate with a secret or with [private key JWT](private-key-jwt.md).
