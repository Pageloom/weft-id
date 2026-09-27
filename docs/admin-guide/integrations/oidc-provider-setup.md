# Sign in with WeftID (OIDC)

WeftID can act as an **OpenID Provider (OP)** so downstream applications can offer a "Sign in with WeftID" button and receive verifiable identity claims. OIDC is layered on top of the [Apps](apps.md) authorization code flow: an OIDC-enabled app receives a signed ID token in addition to the OAuth2 access and refresh tokens.

This page covers registering a downstream app as an OIDC relying party. For the OAuth2 mechanics (authorization code flow, PKCE, token lifetimes), see [Apps](apps.md).

## Enabling OIDC on an app

1. Create an app under **Applications > OAuth2 / OIDC** (or open an existing one).
2. On the app's detail page, find the **OpenID Connect** section and click **Enable OIDC**.

Enabling OIDC changes two behaviors:

* The token endpoint issues a signed RS256 **ID token** whenever the request includes the `openid` scope.
* **Group-based access control** is enforced at login. A user who is not granted access is denied at the authorize step (they never receive a code or token).

Plain OAuth2 apps (OIDC disabled) are unaffected by both changes.

## Discovery URL and endpoints

Once OIDC is enabled, the app detail page shows the read-only **endpoint URLs** for your tenant. Copy these into your downstream application. Most OIDC client libraries need only the discovery URL and will fetch the rest automatically.

* **Issuer** -- `https://<your-tenant-host>`
* **Discovery URL** -- `https://<your-tenant-host>/.well-known/openid-configuration`
* **JWKS URI** -- `https://<your-tenant-host>/.well-known/jwks.json` (public keys for verifying ID token signatures)
* **Authorization endpoint** -- `https://<your-tenant-host>/oauth2/authorize`
* **Token endpoint** -- `https://<your-tenant-host>/oauth2/token`
* **UserInfo endpoint** -- `https://<your-tenant-host>/userinfo`
* **End session endpoint** -- `https://<your-tenant-host>/oauth2/logout` (see [Signing out](#signing-out))

The issuer and every endpoint are scoped to your tenant host. A relying party configured against one tenant's issuer can never receive another tenant's keys or claims.

## Redirect URIs

OIDC uses the same **Redirect URIs** as the app's OAuth2 configuration. Add each callback URL (one per line, exact match, no wildcards) in the app's edit form. After a successful sign-in, WeftID redirects the browser to one of these URIs with the authorization code.

## Signing out

An app can sign the user out of WeftID by sending the browser to the **end session endpoint** (OpenID Connect RP-Initiated Logout). Most OIDC client libraries do this for you once they know the discovery URL.

The endpoint accepts `GET` and `POST` with these parameters:

* `id_token_hint` -- an ID token WeftID issued to your app for this user (an expired one is fine). Strongly recommended.
* `post_logout_redirect_uri` -- where to send the user afterwards. Must exactly match one of the app's **Post-logout redirect URIs**.
* `state` -- any value; it is passed back to the `post_logout_redirect_uri`.
* `client_id` -- optional; must match the `id_token_hint` when both are sent.

What happens:

* With a valid `id_token_hint` for the signed-in user, WeftID signs the user out straight away. The browser then goes to the `post_logout_redirect_uri` (with `state`), or to a "You have signed out" page when none was sent.
* In every other case (no hint, a hint WeftID cannot verify or that names a different user, or a `post_logout_redirect_uri` that is not registered) WeftID asks the user to confirm. After they confirm, they see the "You have signed out" page. WeftID never sends the user to an address it could not verify.

Signing out through the end session endpoint also ends the user's sessions at SAML applications WeftID signed them in to. It does not sign them out of an upstream identity provider (such as Okta or Entra ID) they used to sign in to WeftID. Remembered consent is not affected: signing out ends the session, not the user's decision to allow the app.

### Post-logout redirect URIs

Add each address your app may return to after sign-out in the **Post-logout redirect URIs** box on the app's edit form, one per line. Each must be an absolute `http` or `https` URL without a fragment, and WeftID compares them exactly. Leave the box empty if your app does not need to be sent back. Through the API, set `post_logout_redirect_uris` with `PATCH /api/v1/oauth2/clients/{client_id}`.

## Scopes and claims

WeftID gates released claims by the scopes a relying party **requests** at authorize time. There is no per-app scope allowlist to configure: request the scopes your app needs, and WeftID releases only the matching claims.

Supported scopes and the claims they release:

* `openid` -- required for an ID token. Releases the envelope claims: `sub` (the stable WeftID user id, never the email), `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce` (when supplied), and `sid` (the WeftID session the user signed in with).
* `profile` -- `name`, `given_name`, `family_name`, `locale`, `zoneinfo`, `updated_at`. Claims WeftID has no data for (such as `nickname`, `picture`, or `birthdate`) are left out, never sent empty.
* `email` -- `email`, `email_verified`.
* `groups` -- `groups`, the user's effective group memberships (see below).

The ID token carries only the `openid` envelope claims. The `profile`, `email`, and `groups` claims come from the **UserInfo endpoint**, called with the access token from the same token response. This follows OpenID Connect Core section 5.4 for the authorization code flow, and it keeps personal data out of a token that the app may pass on to other parties. Most OIDC client libraries call UserInfo automatically after sign-in.

The UserInfo endpoint accepts `GET` and `POST`. Send the access token in the `Authorization: Bearer` header, or, with `POST`, as the `access_token` form field (not both). The token must have been issued to an OIDC-enabled app.

## Group-claim behavior

When the `groups` scope is granted, the UserInfo response includes a `groups` claim listing the user's **effective** group names. Effective membership is DAG-aware: it includes groups the user belongs to directly plus all ancestor groups reachable through the group hierarchy. The claim is always present (as an empty list when the user has no groups) whenever the scope is granted, so relying parties can treat "no `groups` claim" and "empty `groups`" unambiguously.

## Controlling who can sign in

OIDC-enabled apps enforce access control at login, mirroring the [SAML service provider](../service-providers/index.md) model:

* **Group-based access** (default) -- Only members of assigned groups, and members of their descendant groups, can sign in. Assign groups in the **Assigned Groups** panel on the app detail page.
* **Available to all users** -- Every active tenant user can sign in. Toggle this in the **Access Mode** panel. Group assignments remain visible but are organizational only.

A denied user sees an access-denied error instead of the consent screen and is never issued a code or token. Denials are recorded in the audit log.

## Managing OIDC via the API

Everything above is available through the REST API under `/api/v1/oauth2/clients/{client_id}`:

* `PATCH /{client_id}/oidc` -- toggle `oidc_enabled` and/or `available_to_all`.
* `GET /{client_id}/oidc/urls` -- fetch the discovery/JWKS/endpoint URLs.
* `GET /{client_id}/groups` -- list assigned groups.
* `POST /{client_id}/groups` -- assign a group (`{"group_id": "..."}`).
* `POST /{client_id}/groups/bulk` -- assign several groups (`{"group_ids": [...]}`).
* `DELETE /{client_id}/groups/{group_id}` -- remove a group assignment.

Redirect URIs and post-logout redirect URIs are managed through the existing `PATCH /{client_id}` endpoint (`redirect_uris`, `post_logout_redirect_uris`).

## Signing key rotation

WeftID signs ID tokens with a per-tenant RSA key, published at the JWKS URI. The key is provisioned automatically the first time it is needed; no setup is required. Operators can inspect and rotate it under `/api/v1/oidc/signing-key`:

* `GET /api/v1/oidc/signing-key` -- current key metadata: `kid`, `algorithm`, `created_at`, plus the retired key's `previous_kid` and `rotation_grace_period_ends_at` while a rotation is in its grace window. Admin role required. No key material is ever returned.
* `POST /api/v1/oidc/signing-key/rotate` -- generate a new signing key. Optional body `{"grace_period_hours": 24}` (1 to 720) controls how long the retired key stays published in the JWKS so relying parties can still verify in-flight ID tokens. Rotation is refused while a prior rotation is still within its grace period. Super admin role required.
* `POST /api/v1/oidc/signing-key/cleanup` -- remove the retired key immediately after its grace period has ended, without waiting for the automatic sweep. A key still within its grace window is never removed. Super admin role required.

New tokens are signed with the new key as soon as the rotation completes. Relying parties that fetch keys from the JWKS URI (the normal case) pick up the change automatically. A background sweep removes retired keys once their grace period lapses; rotations and cleanups are recorded in the audit log.

## Access requirements

Admin or super admin role required to manage OIDC settings and group assignments. Signing-key rotation and cleanup require the super admin role.

## What is not supported

WeftID implements the functional OpenID Provider surface: discovery, JWKS, RS256 ID tokens, UserInfo, scope-gated claims, nonce binding, `prompt`, `max_age`, `login_hint`, `id_token_hint`, the `query` and `form_post` response modes, RP-initiated logout, and group-based access control. The following are not available yet: front-channel and back-channel logout, token introspection and revocation endpoints, the device grant, dynamic client registration, and pairwise subject identifiers.

These parts of the specification are not supported, and discovery says so:

* **Request objects** (`request` and `request_uri`) are rejected with `request_not_supported` or `request_uri_not_supported`.
* **The `claims` request parameter** is ignored (`claims_parameter_supported` is `false`). Claims are released by scope only.
* **No `acr` claim.** WeftID defines no authentication context classes, so `acr_values` is accepted but has no effect.
* **Response types other than `code`** (implicit and hybrid flows).
