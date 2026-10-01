# Client Registration

Normally an admin creates each OAuth2 / OIDC app by hand on **Applications > OAuth2 / OIDC**. With client registration turned on, an application can register itself instead. It sends its details to WeftID and receives a client ID and secret in the response. This is OpenID Connect Dynamic Client Registration (RFC 7591), with client configuration management (RFC 7592).

Use it when software you do not control needs to sign users in through WeftID and knows how to register itself, or when you onboard many apps and want a partner to do it without an admin in the loop.

Client registration is off by default. Turn it on under **Applications > Client Registration**.

## Who can register

* **No one** (default). The registration endpoint is closed and does not appear in discovery.
* **Applications with an initial access token.** An application must present a token you issue on the same page. This is the recommended setting.
* **Anyone.** Any application that can reach your tenant can register. Use this only if you understand the risk: anyone can create an app that asks your users to sign in. The other safeguards below still apply.

While registration is on, the discovery document advertises the endpoint as `registration_endpoint`: `https://<your-tenant-host>/oauth2/register`.

## Who can sign in to a newly registered app

* **No one, until an admin grants access** (default). A registered app starts with no access. Assign groups on the app's page, or make it available to everyone there, before users can sign in.
* **Every user.** Users can sign in right away.

This applies to apps registered after you change it. Users always see the consent page the first time they sign in to a registered app.

## Initial access tokens

Create a token under **Initial access tokens**, give it a name that says who it is for, and optionally an expiry (1 to 365 days). WeftID shows the token once. Copy it and pass it to whoever runs the registering application. They send it as `Authorization: Bearer <token>` when registering.

A token can register any number of apps until it expires or you revoke it. The list shows when each token was last used and how many apps it registered. Revoking a token stops new registrations with it; apps it already registered keep working.

## What an application can register

An application sends its metadata as JSON. WeftID accepts:

* `redirect_uris` (required). Absolute `https` URIs without a fragment. An app with `"application_type": "native"` may also use `http` on a loopback address (`localhost`, `127.0.0.1`, `[::1]`).
* `client_name`, shown to users on the consent page. Without it, WeftID names the app after its first redirect URI's host.
* `logo_uri`, `policy_uri`, `tos_uri`, and `client_uri` (all `https`). The consent page shows the logo and links to the privacy policy and terms of service.
* `grant_types`: `authorization_code`, optionally with `refresh_token`.
* `token_endpoint_auth_method`: `client_secret_basic` (default) or `client_secret_post`.
* `contacts`, `jwks`, or `jwks_uri`. WeftID stores these and returns them, but does not use the keys yet.
* The logout settings an admin can set on an app: `post_logout_redirect_uris`, `frontchannel_logout_uri`, `backchannel_logout_uri`, and their `_session_required` flags.
* `initiate_login_uri` (`https`), the app's URL that starts a sign-in with WeftID. Users who can access the app see it in **My Apps** (see [Launching from My Apps](oidc-provider-setup.md#launching-from-my-apps)).

WeftID rejects metadata it cannot honour rather than quietly ignoring it. That includes other response types, the implicit and client credentials grants, `private_key_jwt` and public clients, unsigned or encrypted ID tokens, signed userinfo, request objects, and pairwise subjects. A rejected request gets HTTP 400 with `invalid_redirect_uri` or `invalid_client_metadata`. Metadata WeftID does not recognise is ignored.

A registered app is always an ordinary OAuth2 / OIDC app with OIDC turned on. An application cannot register a service account.

## After registration

The response contains the client ID and secret, plus a **registration access token** and a `registration_client_uri`. With that token, the application can read (`GET`), replace (`PUT`), or delete (`DELETE`) its own registration at that address. A `PUT` replaces everything: anything left out returns to its default. These calls keep working if you later turn registration off.

Registered apps appear on **Applications > OAuth2 / OIDC** with a **Registered** badge. You manage them like any other app: grant access, edit, deactivate, regenerate the secret, or delete. A deactivated app can no longer use its registration access token.

## Audit events

* `oauth2_client_registered`, `oauth2_client_registration_updated`, `oauth2_client_registration_deleted`. The actor is the system, because no user is involved. The registration event names the initial access token used.
* `oauth2_registration_settings_updated` when an admin changes who can register or the default access.
* `oauth2_initial_access_token_created` and `oauth2_initial_access_token_revoked`.

## API

The settings and tokens are also available under `/api/v1/oauth2/registration`: `GET` and `PATCH /settings`, `GET` and `POST /initial-access-tokens`, and `POST /initial-access-tokens/{id}/revoke`. All require the admin role. Client records on `/api/v1/oauth2/clients` include `dynamically_registered` and the registered `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`, and `initiate_login_uri`.
