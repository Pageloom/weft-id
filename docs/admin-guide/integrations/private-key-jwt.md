# Private Key JWT

An app or service account usually proves who it is with its client secret. With **private key JWT** (`private_key_jwt`, RFC 7523 and OpenID Connect Core section 9) it signs a short-lived JWT with its own private key instead. WeftID keeps only the public keys, so there is no shared secret to leak, rotate by hand, or paste into a config file.

Private key JWT works at every endpoint where a client authenticates: the token endpoint (every grant), device authorization, token introspection, and token revocation.

## Turning it on

Open the app or service account and find **Client Authentication**:

1. Choose **Private key JWT**.
2. Give WeftID the client's public keys, either:
    * **Paste public keys (JWKS)**: a JSON Web Key Set of RSA or EC public keys, at most 20. Never paste a private key; WeftID refuses a set that contains private key material.
    * **Fetch from a URL**: an `https` URL where the client publishes its key set. WeftID fetches it, caches it for an hour, and fetches it again when the client signs with a key it hasn't seen yet, so the client can rotate keys without an admin.
3. Click **Save Authentication** and confirm.

The client secret stops working as soon as you switch. Switching back to **Client secret** generates a new secret, shown once.

Through the API, send `PUT /api/v1/oauth2/clients/{client_id}/authentication` with `method` (`client_secret` or `private_key_jwt`) and either `jwks` or `jwks_uri`. Service accounts need the super admin role. An application that registers itself can ask for `private_key_jwt` too (see [Client Registration](client-registration.md)).

A [public client](device-sign-in.md#public-clients) has no client authentication to change.

## Signing a client assertion

The client sends two form fields in place of its secret:

```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed JWT>
```

`client_id` is optional; when sent, it must match the assertion. Don't send a secret or an `Authorization` header in the same request.

The JWT must:

* Be signed with RS256, PS256, or ES256 by one of the registered keys. Put the key's `kid` in the header when the set has more than one key. If the client registered a `token_endpoint_auth_signing_alg`, only that algorithm is accepted.
* Have `iss` and `sub` both set to the client ID.
* Have an `aud` naming WeftID: the issuer (`https://<tenant-host>`), the token endpoint URL, or the URL of the endpoint being called.
* Have an `exp` no more than an hour away. Assertions are meant to be made fresh for each request; a lifetime of a minute or two is typical.
* Have a unique `jti`. WeftID accepts each `jti` once per client, so a captured assertion can't be replayed.

Any failure gets HTTP 401 with `{"error": "invalid_client"}`, the same answer as a wrong secret. WeftID logs the reason on the server, never the assertion.

## Discovery

The discovery document lists `private_key_jwt` in `token_endpoint_auth_methods_supported`, `introspection_endpoint_auth_methods_supported`, and `revocation_endpoint_auth_methods_supported`, and the accepted algorithms in the matching `..._auth_signing_alg_values_supported` fields.

## Not supported

* `client_secret_jwt` (an assertion signed with the client secret). Use the secret directly, or move to private key JWT.
* Mutual TLS client authentication (RFC 8705).
