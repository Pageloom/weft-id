# Sign in with WeftID (OIDC)

WeftID can act as an **OpenID Provider (OP)** so downstream applications can offer a "Sign in with WeftID" button and receive verifiable identity claims. OIDC is layered on top of the [Apps](apps.md) authorization code flow: an OIDC-enabled app receives a signed ID token in addition to the OAuth2 access and refresh tokens.

This page covers registering a downstream app as an OIDC relying party. For the OAuth2 mechanics (authorization code flow, PKCE, token lifetimes), see [Apps](apps.md).

## Enabling OIDC on an app

1. Create an app under **Admin > Integrations > Apps** (or open an existing one).
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

The issuer and every endpoint are scoped to your tenant host. A relying party configured against one tenant's issuer can never receive another tenant's keys or claims.

## Redirect URIs

OIDC uses the same **Redirect URIs** as the app's OAuth2 configuration. Add each callback URL (one per line, exact match, no wildcards) in the app's edit form. After a successful sign-in, WeftID redirects the browser to one of these URIs with the authorization code.

## Scopes and claims

WeftID gates released claims by the scopes a relying party **requests** at authorize time. There is no per-app scope allowlist to configure: request the scopes your app needs, and WeftID releases only the matching claims.

Supported scopes and the claims they release:

* `openid` -- required for an ID token. Releases the envelope claims: `sub` (the stable WeftID user id, never the email), `iss`, `aud`, `exp`, `iat`, `auth_time`, and `nonce` (when supplied).
* `profile` -- `name`, `given_name`, `family_name`, `locale`, `updated_at`.
* `email` -- `email`, `email_verified`.
* `groups` -- `groups`, the user's effective group memberships (see below).

The same scope-gated claims are available from both the ID token and the UserInfo endpoint. A UserInfo request must present an access token issued to an OIDC-enabled app.

## Group-claim behavior

When the `groups` scope is granted, the ID token and UserInfo response include a `groups` claim listing the user's **effective** group names. Effective membership is DAG-aware: it includes groups the user belongs to directly plus all ancestor groups reachable through the group hierarchy. The claim is always present (as an empty list when the user has no groups) whenever the scope is granted, so relying parties can treat "no `groups` claim" and "empty `groups`" unambiguously.

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

Redirect URIs are managed through the existing `PATCH /{client_id}` endpoint.

## Access requirements

Admin or super admin role required to manage OIDC settings and group assignments.

## What is not supported

WeftID implements the functional OpenID Provider surface: discovery, JWKS, RS256 ID tokens, UserInfo, scope-gated claims, nonce binding, and group-based access control. The following are intentionally out of scope: RP-initiated and back-channel logout, token introspection and revocation endpoints, the device grant, dynamic client registration, pairwise subject identifiers, and remembered/revocable consent.
