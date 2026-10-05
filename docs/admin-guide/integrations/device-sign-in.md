# Device Sign-In

Device sign-in lets an app on a device without a convenient browser, such as a command-line tool, a TV, or a kiosk, sign a user in through WeftID. The device shows a short code. The user opens a page on their phone or computer, signs in to WeftID, enters the code, and approves. The device then receives its tokens. This is the OAuth 2.0 device authorization grant (RFC 8628).

## Turning it on

Device sign-in is off for every app until you turn it on:

1. Open the app under **Applications > OAuth2 / OIDC**.
2. Check **Allow device sign-in** on the edit form and save.

Through the API, set `device_grant_enabled` to `true` with `POST` or `PATCH /api/v1/oauth2/clients/{client_id}`. Service accounts can't use device sign-in.

## Public clients

A TV app or a command-line tool you hand out to users can't keep a client secret: anyone who has the app can read it. For these, create a **public client**. A public client has no secret and identifies itself by its client ID alone.

To create one, check **Public client (device sign-in only)** in the **Create App** dialog. Through the API, send `"is_public": true` with `POST /api/v1/oauth2/clients`. You can't make an existing app public, or turn a public app into one with a secret. Create a new app instead.

A public client:

* Signs in with device sign-in only, which is always on for it. It can also refresh its tokens.
* Has no redirect URIs, so it can't use the authorization endpoint. It has no post-logout redirect URIs, front-channel logout URI, or login initiation URI either. A back-channel logout URI is allowed.
* Sends `client_id` with no `client_secret` and no `Authorization` header at the device authorization, token, and revocation endpoints. It can't use the introspection endpoint.
* Has no secret to regenerate.

Every other rule on this page applies unchanged. Users still confirm every sign-in on the `/device` page, and refresh tokens are rotated on every use, so a stolen refresh token stops working once either party uses it.

An application can also register itself as a public client through [client registration](client-registration.md) with `"token_endpoint_auth_method": "none"`.

## How the device signs in

1. The device asks for a code at the device authorization endpoint, authenticating with its client ID and secret the same way as at the token endpoint (a public client sends `client_id` alone):

    ```
    POST /oauth2/device_authorization
    client_id=...&client_secret=...&scope=openid profile email
    ```

    The response carries a `device_code`, a `user_code` such as `BCDF-GHJK`, the `verification_uri` (`https://<your-tenant-host>/device`), a `verification_uri_complete` with the code filled in (handy for a QR code), `expires_in` (600 seconds), and `interval` (5 seconds).

2. The device shows the user the code and the verification address.

3. While the user approves, the device polls the token endpoint no more often than every `interval` seconds:

    ```
    POST /oauth2/token
    grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=...&client_id=...&client_secret=...
    ```

    Until the user decides, the answer is the error `authorization_pending`. Polling too fast returns `slow_down`, and the device must then wait 5 more seconds between polls from then on. Once the user approves, the next poll returns an access token and a refresh token, plus an ID token when the app has OIDC turned on and asked for the `openid` scope. The tokens are issued once. Later polls with the same device code return `invalid_grant`.

4. If the user denies, the poll returns `access_denied`. If 10 minutes pass first, it returns `expired_token`, and the device has to start again.

## What the user sees

The user goes to `/device`, signs in if they are not already, and types the code. Codes are not case-sensitive, and the dash is optional. WeftID then shows a confirmation page naming the app, the code, and what it asks for. The user picks **Allow** or **Deny**. The page always asks, even if the user has allowed the app before. Typing the code and confirming it is how the user shows that they started the sign-in themselves.

A link with the code already filled in (`verification_uri_complete`) only fills in the form. The user still has to press **Continue** and then **Allow**.

## Access and security

* Group-based access applies as for any OIDC app (see [Controlling who can sign in](oidc-provider-setup.md#controlling-who-can-sign-in)). A user without access is turned away on the confirmation page, and access is checked again when the device collects its tokens.
* Entering codes is rate limited per user.
* Approving records the user's consent, so the app appears under **User Settings > Authorized Apps**.
* Tokens from device sign-in are not tied to the browser session the user approved from. Signing out of WeftID in that browser does not sign the device out. Deactivating the user, deactivating the app, or revoking the user's tokens does.
* ID tokens from device sign-in carry `auth_time` (when the approving browser session signed in) but no `sid`, because no browser session belongs to the device.

## Audit events

* **Device sign-in started by an application** -- the device asked for a code (operational).
* **User approved a device sign-in** and **User denied a device sign-in** -- the user's decision.
* **Device sign-in completed; tokens issued to the device** -- the device collected its tokens.
