# Apps

Apps are OAuth2 clients that use the authorization code flow. They're designed for web applications, mobile apps, and other interactive applications where a user authorizes access through a consent screen.

## Creating an app

Navigate to **Applications > OAuth2 / OIDC** and click **Create App**.

| Field | Required | Description |
|-------|----------|-------------|
| Name | Yes | Display name shown to users on the consent screen (max 255 characters) |
| Description | No | Internal description (max 500 characters) |
| Redirect URIs | Yes | One URI per line. Exact match required, no wildcards. These are the URLs the user is redirected to after authorization. |

After creation, WeftID displays the **client ID** and **client secret** in a dialog. Copy and store these credentials securely. The secret is not retrievable after you dismiss the dialog.

## Authorization code flow

1. Your application redirects the user to WeftID's authorization endpoint:

    ```
    GET /oauth2/authorize?response_type=code&client_id=...&redirect_uri=...&state=...
    ```

2. The user sees a consent screen showing your application's name, their identity, and the requested scopes. They click **Allow** or **Deny**. WeftID remembers an **Allow** per user and application: later requests for the same (or a subset of the) scopes skip the screen, and `prompt=none` succeeds silently. A request for a scope the user has not allowed shows the screen again with the already-allowed scopes marked, and `prompt=consent` always shows it.

3. If allowed, WeftID redirects to your `redirect_uri` with an authorization code:

    ```
    https://your-app.com/callback?code=...&state=...
    ```

    To receive the code in a form POST instead of the URL, add
    `response_mode=form_post` to the authorization request. WeftID then
    renders a page that submits `code` and `state` to your `redirect_uri` as
    form fields. Errors (for example `access_denied`) are delivered the same
    way as the code.

4. Your application exchanges the code for tokens at the token endpoint:

    ```
    POST /oauth2/token
    grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&client_secret=...
    ```

    The client credentials can be sent either as the `client_id` and
    `client_secret` form fields shown above (`client_secret_post`) or as an
    HTTP Basic `Authorization` header (`client_secret_basic`). Use one method
    per request, not both. An app set to [private key JWT](private-key-jwt.md)
    sends a signed `client_assertion` instead of a secret.

5. WeftID returns an access token and refresh token:

    ```json
    {
      "access_token": "...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": "..."
    }
    ```

    Fields that do not apply are left out of the response, not sent as
    `null`. Token responses are marked `Cache-Control: no-store`.

An authorization code works once. If the same code is redeemed a second time,
WeftID rejects the request and revokes every token already issued from that
code, since a reused code means it has leaked.

### Token endpoint errors

Errors follow RFC 6749: a JSON object with `error` and `error_description`
at the top level.

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid or expired authorization code"
}
```

Errors use HTTP 400, except `invalid_client` (unknown client or wrong
secret), which uses HTTP 401 with a `WWW-Authenticate: Basic` header.

### PKCE support

WeftID supports Proof Key for Code Exchange (PKCE), which binds the authorization code to the client that asked for it. The token exchange still needs the client secret: a public client (no secret) can sign users in only with [device sign-in](device-sign-in.md#public-clients). Include `code_challenge` and `code_challenge_method` in the authorization request, and `code_verifier` in the token exchange. Supported methods: `S256` (recommended) and `plain`.

### Pushed authorization requests

A confidential app can send its authorization request to `POST /oauth2/par` first, server to server, and then send the browser with only the returned `request_uri` (RFC 9126). Turn on **Require pushed authorization requests** on the app's edit form to refuse that app's sign-ins any other way. See [Pushed authorization requests](oidc-provider-setup.md#pushed-authorization-requests).

### Token lifetimes

| Token | Lifetime |
|-------|----------|
| Authorization code | 5 minutes |
| Device code (device sign-in) | 10 minutes |
| Access token | 1 hour |
| Refresh token | 30 days |

Use the refresh token to obtain new access tokens without requiring the user to re-authorize:

```
POST /oauth2/token
grant_type=refresh_token&refresh_token=...&client_id=...&client_secret=...
```

Refresh tokens rotate. Each refresh returns a new access token **and a new
refresh token**, and the refresh token you sent stops working immediately.
Store the new one each time. Rotation does not extend the 30 days: the new
refresh token expires when the original one would have. Access tokens issued
earlier stay valid until they expire. A refresh token only works for the app
it was issued to. A refresh token issued with an OIDC ID token (the `openid`
scope) also ends when the user signs out of WeftID; see
[Refresh tokens end with the session](oidc-provider-setup.md#refresh-tokens-end-with-the-session).

An app can check or revoke its own tokens at the introspection and revocation
endpoints; see [Token Introspection and Revocation](token-introspection.md).

## Device sign-in

An app on a device without a convenient browser (a command-line tool, a TV)
can sign users in with a short code they enter on another screen. Turn on
**Allow device sign-in** on the app's edit form. An app that can't keep a secret,
such as one installed on users' own devices, can be created as a **public client**
with no secret. See [Device Sign-In](device-sign-in.md).

## Sign in with WeftID (OIDC)

Apps can act as OpenID Connect relying parties, receiving a signed ID token and identity claims in addition to OAuth2 tokens. Enable OIDC from the app's detail page to get a discovery URL, scope-gated claims, and group-based access control. See [Sign in with WeftID (OIDC)](oidc-provider-setup.md).

## Managing an app

Click the app name in the list to open its detail page. From there you can:

- **Edit** the name, description, and redirect URIs
- **Enable OIDC** -- Turn the app into an OpenID Connect provider (see [Sign in with WeftID (OIDC)](oidc-provider-setup.md)).
- **Regenerate the client secret** -- Immediately invalidates the old secret. A new secret is shown once.
- **Change client authentication** -- Switch between a client secret and [private key JWT](private-key-jwt.md), and set the app's public keys.
- **Deactivate** -- Disables the client, revokes all active tokens, and forgets every user's consent. The app can be reactivated later.
- **Reactivate** -- Re-enables a deactivated app. Users will need to re-authorize.
- **Allow token introspection for all tenant tokens** -- For an app whose backend acts as a resource server. See [Token Introspection and Revocation](token-introspection.md).
- **Revoke a user's consent** -- The **User Consents** section lists every user who allowed the app and the scopes they granted. Revoking one makes that user see the consent screen again on their next sign-in; it does not revoke tokens the app already holds. Users can also revoke their own consents under **User Settings > Authorized Apps**.

## Access requirements

Admin or super admin role required to manage apps.
