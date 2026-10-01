# Token Introspection and Revocation

WeftID access and refresh tokens are opaque strings. Nothing can be read from the token itself, so a service that receives one asks WeftID about it. WeftID offers two standard endpoints for this:

* **Introspection** (RFC 7662) -- `POST https://<your-tenant-host>/oauth2/introspect`. Is this token valid, and whose is it?
* **Revocation** (RFC 7009) -- `POST https://<your-tenant-host>/oauth2/revoke`. Stop this token working now.

Both are advertised in the discovery document as `introspection_endpoint` and `revocation_endpoint`.

## Who calls these endpoints

Any OAuth2 client (an app or a service account) can call both endpoints, authenticating with its own client ID and secret. Both are machine-to-machine calls. Users never see them.

The typical caller of the introspection endpoint is a **resource server**: an API backend that receives requests carrying `Authorization: Bearer <token>`. The backend never signed anyone in. It needs to know whether the token is valid, which user it belongs to, and which scopes it carries.

## Client authentication

Use the same two methods the token endpoint accepts:

* **HTTP Basic** (`client_secret_basic`) -- `Authorization: Basic base64(client_id:client_secret)`
* **Form fields** (`client_secret_post`) -- `client_id` and `client_secret` in the request body

Use one method per request, not both. A wrong secret, an unknown client, or a deactivated client gets HTTP 401 with `{"error": "invalid_client"}`.

## Introspecting a token

```
POST /oauth2/introspect
Authorization: Basic ...
Content-Type: application/x-www-form-urlencoded

token=<the access or refresh token>
```

`token_type_hint` (`access_token` or `refresh_token`) is accepted and ignored. WeftID finds the token either way.

A valid token the caller may see returns:

```json
{
  "active": true,
  "scope": "openid email",
  "client_id": "weft-id_client_abc123",
  "sub": "4f6e1c2a-...",
  "token_type": "Bearer",
  "exp": 1790000000,
  "iat": 1789996400,
  "iss": "https://<your-tenant-host>"
}
```

* `client_id` -- the app the token was issued to
* `sub` -- the user's ID, the same value as the `sub` claim in ID tokens and UserInfo. For a service account token it is the service user's ID.
* `scope` -- left out when the token carries no scopes
* `token_type` -- present for access tokens only

Anything else returns only `{"active": false}`: an unknown, expired, or revoked token, or a token the caller is not allowed to see. The response does not say which. Responses are marked `Cache-Control: no-store`.

### Which tokens a client can see

By default a client can introspect only the tokens issued to it. A token issued to another app returns `{"active": false}`.

If your API backend receives tokens issued to several apps, register the backend as its own client (usually a [service account](b2b.md)) and turn on **Introspect all tenant tokens** on its detail page under **Token Introspection**. That client can then introspect every token in the tenant.

Turn this on only for clients you trust with that view. The client can see which user, app, and scopes sit behind any token in the tenant. It cannot revoke tokens issued to other apps.

The setting is off by default. On the API it is `can_introspect_tenant_tokens` on `PATCH /api/v1/oauth2/clients/{client_id}`. Changing it is audited as `oauth2_client_introspection_changed`.

### Caching

Each call verifies the client secret and the token, so introspecting on every request adds a round trip to WeftID. A resource server may cache an `active: true` result for a short time (a minute or so). Keep the cache shorter than `exp`. While a result is cached, a token revoked in WeftID can still be accepted.

## Revoking a token

```
POST /oauth2/revoke
Authorization: Basic ...
Content-Type: application/x-www-form-urlencoded

token=<the access or refresh token>
```

* **Refresh token** -- the refresh token stops working, and so does every access token issued from it.
* **Access token** -- only that access token stops working. Its refresh token keeps working.

A client can revoke only its own tokens, even if it may introspect all tenant tokens.

Once the client authenticates, the response is always HTTP 200 with an empty body. This includes unknown, expired, already revoked, and other apps' tokens, so the response never reveals whether a token exists. Revoking a token is audited as `oauth2_token_revoked`. Revoking an unknown or another app's token is not.

Call the revocation endpoint when a user signs out of your app, so its tokens don't outlive the sign-out. For apps using Sign in with WeftID, tokens issued with an ID token already end with the WeftID session (see [Refresh tokens end with the session](oidc-provider-setup.md#refresh-tokens-end-with-the-session)).

## Errors

Errors use the same format as the token endpoint: a JSON object with `error` and `error_description`.

* `invalid_client` (HTTP 401) -- missing, wrong, or conflicting client credentials, or a deactivated client
* `invalid_request` (HTTP 400) -- the `token` parameter is missing or longer than 255 characters

## Logging

Introspection is a high-volume machine call, so it is not written to the audit log. Each call writes one line to the application log (the calling client and the outcome, never the token). Revocations are audited.

## Access requirements

Admin or super admin role required to change the setting on an app. Super admin role required on a service account.
