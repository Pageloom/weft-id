# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.0.0] - 2026-10-03

A major release because existing OAuth2 / OIDC apps and SAML identity
providers may need changes. Read the entries marked **BREAKING** under
[Changed](#changed) before upgrading.

### Added

- **Relying-party conformance for upstream OIDC.** WeftID's upstream OpenID
  Connect connector now runs the OpenID Foundation suite's Basic RP,
  Config RP, RP-Initiated RP and Back-Channel RP profiles (the suite plays
  the identity provider) and passes all four; results are on the
  [conformance page](docs/conformance/oidc.md#relying-party-profiles).
- **Sign-out at the provider sends `state`.** With **Sign Out at the
  Provider** on, WeftID's end session request to the upstream provider now
  carries a random `state`. An app's post-logout redirect is honoured on
  the way back only when the provider returns that same value; otherwise
  the browser lands on the sign-in page.
- **Upstream OIDC discovery stays current.** A connection whose endpoints
  came from discovery refetches the provider's discovery document at sign-in
  once the last fetch is more than an hour old. If the document cannot be
  reached, sign-in uses the last known endpoints; if it is refused (wrong
  issuer, non-`https` endpoint), sign-in stops with a configuration error.
  Hand-entered endpoints are not refreshed. **Test connection** now also
  fetches the provider's signing keys, is available as
  `POST /api/v1/oidc-upstream/connections/{connection_id}/test`, and is
  audited (`oidc_idp_connection_tested`).

- **Pairwise subject identifiers.** An app can receive a pairwise `sub`
  (OpenID Connect Core section 8) instead of the user's WeftID ID, so apps in
  different sectors can't match users by `sub`. It is an opt-in per app:
  **Subject Identifiers** on the app's OpenID Connect section,
  `PUT /api/v1/oauth2/clients/{client_id}/subject`, or `subject_type` and
  `sector_identifier_uri` at client registration. The sector is the host of
  the app's redirect URIs, or of its sector identifier URI (fetched through
  the SSRF guard and checked to list every redirect URI). The pairwise value
  is used in ID tokens, UserInfo, introspection, back-channel logout tokens,
  and `id_token_hint` checks. Discovery lists `pairwise` in
  `subject_types_supported`. See
  [Pairwise Subject Identifiers](docs/admin-guide/integrations/pairwise-subjects.md).
- **Pushed authorization requests (PAR, RFC 9126).** A confidential app can
  post its authorization request to `POST /oauth2/par` (authenticated like
  the token endpoint) and send the browser to the authorization endpoint with
  only the returned `request_uri`, which works once, for 60 seconds, and only
  for that app. Parameter errors come back as JSON straight away. Admins can
  require PAR for an app (**Require pushed authorization requests** on its
  edit form, `require_pushed_authorization_requests` in the API and at
  client registration). Discovery advertises
  `pushed_authorization_request_endpoint`. See
  [Pushed authorization requests](docs/admin-guide/integrations/oidc-provider-setup.md#pushed-authorization-requests).
- **Request objects and signed UserInfo.** Apps can send their authorization
  request inside a signed JWT (OpenID Connect Core section 6), by value
  (`request`) or by reference (`request_uri`, an `https` URL the app
  registered in `request_uris`, fetched through the SSRF guard). Request
  objects must be signed with RS256, PS256, or ES256 by one of the app's keys;
  unsigned objects are refused. Apps registered with
  `userinfo_signed_response_alg` get UserInfo as a signed JWT. Dynamic client
  registration accepts `request_uris`, `request_object_signing_alg`, and
  `userinfo_signed_response_alg`, and discovery advertises request object
  and UserInfo signing algorithms. See
  [Request objects and signed UserInfo](docs/admin-guide/integrations/oidc-provider-setup.md#request-objects-and-signed-userinfo).
- **Private key JWT client authentication.** An app or service account can
  prove who it is with a short-lived JWT signed by its own private key
  (`private_key_jwt`, RFC 7523) instead of a client secret, at the token,
  device authorization, introspection, and revocation endpoints. Choose
  **Private key JWT** under **Client Authentication** on the app or service
  account page and paste its public keys or give a JWKS URL, or use
  `PUT /api/v1/oauth2/clients/{client_id}/authentication`. Assertions are
  checked for signature (RS256, PS256, ES256), issuer, audience, expiry, and
  a single-use `jti`. Keys at a URL are fetched through the SSRF guard,
  cached, and refetched when the client rotates. Dynamic client registration
  accepts `private_key_jwt` with `jwks` or `jwks_uri` and
  `token_endpoint_auth_signing_alg`, and discovery lists the method and its
  algorithms. See [Private Key JWT](docs/admin-guide/integrations/private-key-jwt.md).
- **Device sign-in (OAuth 2.0 device authorization grant).** Apps on
  devices without a convenient browser, such as command-line tools and TVs,
  can sign users in with a short code (RFC 8628). Turn on **Allow device
  sign-in** on an app's edit form, or set `device_grant_enabled` on
  `/api/v1/oauth2/clients`. The device calls the new
  `/oauth2/device_authorization` endpoint (advertised in discovery) and polls
  the token endpoint with the `urn:ietf:params:oauth:grant-type:device_code`
  grant. The user enters the code at `/device` and approves on a
  confirmation page. See [Device Sign-In](docs/admin-guide/integrations/device-sign-in.md).
- **Public clients for device sign-in.** An app that can't keep a secret,
  such as a TV app or a command-line tool, can be created as a public client
  (**Public client (device sign-in only)** in the Create App dialog, or
  `is_public` on `POST /api/v1/oauth2/clients`). It has no secret, sends its
  `client_id` alone (`token_endpoint_auth_method` `none`), and may use only
  device sign-in and refresh tokens. It can revoke its tokens but not
  introspect them. Dynamic client registration accepts the device grant
  (`urn:ietf:params:oauth:grant-type:device_code`) and, for device-only
  apps, `none`. Discovery lists `none` for the token and revocation
  endpoints.
- **OIDC apps in My Apps (third-party-initiated login).** An OIDC app can
  now be launched from the dashboard like a SAML application. Set its
  **Login initiation URI** (the app's `https` URL that starts a sign-in) on
  the app's edit form, as `initiate_login_uri` on `/api/v1/oauth2/clients`,
  or in a dynamic registration (returned by the client configuration
  endpoint). Users who can access the app see it in My Apps, and opening it
  sends them to that URI with `iss` (OpenID Connect Core section 4).
  `GET /api/v1/my-apps` returns these apps with `kind: "oidc"`.
- **OpenID Foundation conformance.** WeftID's OpenID Provider passes the
  OpenID Foundation conformance suite (release 5.2.4) for the Basic OP,
  Config OP, Form Post OP, RP-Initiated OP, Front-Channel OP,
  Back-Channel OP, Dynamic OP, and 3rd Party-Init OP profiles. The one
  failure is accepted: a Dynamic OP must also offer the implicit and hybrid
  response types, which WeftID does not. The same tests also pass with apps
  that authenticate with `private_key_jwt`. The accepted failure and
  warnings (no `acr` claim, no `claims` request parameter, a partial
  `profile` claim set) and expected skips are listed with their reasons on
  the new [OpenID Connect Conformance](docs/conformance/oidc.md) docs page,
  along with how to rerun the suite. A CI workflow runs it on the E2E
  schedule and publishes the results with each run. This is conformance
  evidence, not the OpenID Certified mark.
- **RP-initiated logout (OIDC).** Apps can sign users out of WeftID through
  the new end session endpoint, `/oauth2/logout` (advertised in discovery as
  `end_session_endpoint`, `GET` and `POST`). With a valid `id_token_hint` the
  user is signed out at once and sent to the app's registered post-logout
  redirect URI with `state`; otherwise WeftID asks the user to confirm and
  never redirects to an unverified address. Downstream SAML sessions are
  ended as with the sign-out button. Apps register **Post-logout redirect
  URIs** on their edit form or as `post_logout_redirect_uris` on
  `/api/v1/oauth2/clients`. Audited as `user_signed_out` with reason
  `rp_initiated_logout`. Migration 0063.
- **Front-channel logout (OIDC).** Apps can register a **Front-channel
  logout URI** (edit form, or `frontchannel_logout_uri` on
  `/api/v1/oauth2/clients`). When a WeftID session ends (sign-out button,
  end session endpoint, or a forced re-authentication), a short "Signing you
  out" page loads that URI in a hidden frame for every app that received an
  ID token in the session, then continues. The request carries `iss` and
  `sid` unless the app turns off **Send the issuer and session ID**
  (`frontchannel_logout_session_required`, on by default). The URI must share a redirect URI's scheme, host and port. Discovery
  advertises `frontchannel_logout_supported` and
  `frontchannel_logout_session_supported`. The `user_signed_out` audit event
  records `frontchannel_logout_count`. Migration 0064.
- **Back-channel logout (OIDC).** Apps can register a **Back-channel logout
  URI** (edit form, or `backchannel_logout_uri` on `/api/v1/oauth2/clients`).
  When a WeftID session ends (the same three ways), WeftID sends a signed
  logout token to that URI, server to server, for every app that received an
  ID token in the session. The token carries `sub`, and `sid` unless the app
  turns off **Include the session ID** (`backchannel_logout_session_required`,
  on by default). Delivery runs in the background worker within about ten
  seconds and is retried for several hours when the app is unreachable; a
  delivery that is given up is audited as `oidc_backchannel_logout_failed`.
  Discovery advertises `backchannel_logout_supported` and
  `backchannel_logout_session_supported`. The `user_signed_out` audit event
  records `backchannel_logout_count`. Deactivating, anonymizing or deleting a
  user (by an admin, SCIM, the inactivity job, or removal from an identity
  provider) also sends a logout token for each of the user's sessions. The
  app's detail page lists recent deliveries (status, attempts, last error),
  and `GET /api/v1/oauth2/clients/{client_id}/backchannel-logout-deliveries`
  pages through them. Migrations 0065 and 0066.
- **Sign-out from upstream OIDC providers.** Each OIDC identity provider
  connection has a **Back-Channel Logout URL** (Details tab, and
  `backchannel_logout_url` on `/api/v1/oidc-upstream`). Registered at the
  provider, it lets the provider sign users out of WeftID: a signed logout
  token ends every WeftID session that began with the named provider session
  (or, when the token names only the user, every session the user started
  through that connection), notifies downstream apps by back-channel logout,
  and revokes their refresh tokens. Audited as `user_signed_out` with reason
  `upstream_backchannel_logout`; a rejected or replayed token is audited as
  `oidc_idp_logout_rejected`. Migration 0067.
- **Sign-out at upstream OIDC providers.** An OIDC identity provider
  connection can sign users out of the provider when they sign out of
  WeftID (OpenID Connect RP-Initiated Logout). Turn on **Sign Out at the
  Provider** (`sign_out_at_idp` on `/api/v1/oidc-upstream`, off by default)
  and register the connection's **Post-Logout Redirect URI**
  (`post_logout_redirect_uri`) at the provider. The provider's end session
  endpoint is read from discovery or entered by hand
  (`end_session_endpoint`). Logouts started by an app through WeftID's end
  session endpoint also go through the provider, then back to the app.
  Migration 0068.
- **Signing out at a SAML identity provider ends the WeftID session.** A
  logout request the IdP sends through the browser now ends the matching
  WeftID session (same IdP, name ID and session index) instead of only being
  acknowledged. The request must be signed by the IdP and addressed to
  WeftID. Audited as `user_signed_out` with reason `upstream_saml_slo`, or
  `saml_idp_logout_rejected` when refused.
- **`sid` claim.** ID tokens now carry `sid`, an opaque identifier of the
  WeftID session the user signed in with, renewed at every sign-in.
- **Remembered consent.** WeftID now remembers a user's **Allow** on the
  OAuth2 / OIDC consent screen per application and scope set. Later
  authorization requests covered by the grant skip the screen, `prompt=none`
  completes silently, and `prompt=consent` still shows it. A request for a
  scope not yet allowed shows the screen with the already-allowed scopes
  marked. Users see and revoke their grants under **User Settings >
  Authorized Apps** (`/api/v1/account/authorized-apps`); admins see and
  revoke them per app on the app's detail page
  (`/api/v1/oauth2/clients/{client_id}/consents`). Deactivating an app or a
  user forgets the grants; deleting an app cascades. Audit events
  `oauth2_consent_granted`, `oauth2_consent_widened`, and
  `oauth2_consent_revoked`. Migration 0061.
- **OIDC upstream group claim handling.** An OIDC connection can name a group
  claim (Claim mapping tab, or `group_claim_source` and
  `group_claim_name_key` on the API). On every sign-in the claim's values are
  synced into read-only IdP groups beneath the connection's base group,
  exactly as SAML group assertions are. Lists of names, lists of objects, and
  single values are accepted. An absent claim leaves memberships untouched,
  and Entra group overage is detected and recorded as an
  `oidc_group_claim_overage` event instead of emptying the user's groups.
- Every OIDC connection now has a base group named after it, created with the
  connection, renamed with it, and deleted with it. Every user who signs in
  through the connection is added to it, mirroring SAML identity providers.
- **`response_mode=form_post`.** The authorization endpoint can deliver the
  code (and any error) to the redirect URI as an auto-submitting form POST
  instead of a query string. Discovery advertises
  `response_modes_supported: ["query", "form_post"]`.
- **UserInfo over POST.** `/userinfo` accepts `POST` as well as `GET`, with
  the access token in the `Authorization: Bearer` header or, for `POST`, the
  `access_token` form field.
- The `profile` scope now releases `zoneinfo` (the user's time zone).
- **Authorization code reuse revokes the grant.** Redeeming a code a second
  time is rejected and revokes every token already issued from it. Audit
  event `oauth2_authorization_code_reused`. Migration 0062.
- **Token introspection and revocation.** `POST /oauth2/introspect`
  (RFC 7662) tells a resource server whether a token is active and returns
  its user (`sub`), app (`client_id`), scopes, and expiry. `POST
  /oauth2/revoke` (RFC 7009) revokes an access or refresh token; revoking a
  refresh token also revokes the access tokens issued from it. Both
  authenticate the calling client the same way as the token endpoint and are
  advertised in discovery. A client sees and revokes only its own tokens. An
  admin can let one client introspect every token in the tenant (**Token
  Introspection** on the app or service account page, or
  `can_introspect_tenant_tokens` on `/api/v1/oauth2/clients`), for an API
  backend that receives tokens issued to several apps. Revocations are
  audited as `oauth2_token_revoked`, the setting as
  `oauth2_client_introspection_changed`. See the new
  [Token Introspection and Revocation](docs/admin-guide/integrations/token-introspection.md)
  page. Migration 0069.
- **Dynamic client registration.** Applications can register themselves as
  OAuth2 / OIDC apps at `POST /oauth2/register` (OpenID Connect Dynamic
  Client Registration, RFC 7591) and read, replace, or delete their
  registration with the registration access token they receive (RFC 7592).
  Off by default: **Applications > Client Registration** (or
  `/api/v1/oauth2/registration`) sets who may register (no one, holders of
  an admin-issued initial access token, or anyone) and whether a new app is
  available to every user or to no one until an admin grants access.
  Registered apps carry a **Registered** badge and are managed like any
  other app. The consent page now shows an app's registered logo and
  privacy policy and terms links. The endpoint is advertised in discovery
  only while registration is on. Audited as `oauth2_client_registered`,
  `oauth2_client_registration_updated`, `oauth2_client_registration_deleted`,
  `oauth2_registration_settings_updated`,
  `oauth2_initial_access_token_created`, and
  `oauth2_initial_access_token_revoked`. See the new
  [Client Registration](docs/admin-guide/integrations/client-registration.md)
  page. Migration 0070.
- **Registration access tokens rotate and can be reset.** Every
  configuration update (`PUT`) by a dynamically registered client returns a
  new registration access token and the old one stops working. Admins can
  issue a new one with **Reset Registration Access Token** on the app's page
  or `POST /api/v1/oauth2/registration/clients/{client_id}/reset-registration-token`
  (audited as `oauth2_client_registration_token_reset`). The
  `oauth2_client_registration_updated` event now records every changed field.
- A [security policy](SECURITY.md): how to report a vulnerability privately,
  response times, and which versions receive fixes.

### Fixed

- The upstream OIDC connector refused an ID token without a `kid` header
  even when the provider publishes a single signing key (allowed by OpenID
  Connect Core section 10.1). It now uses that key; with several keys the
  token is still refused.
- The upstream OIDC connector merged a userinfo response without checking
  that its `sub` matches the ID token's (OpenID Connect Core section 5.3.2).
  A mismatch now fails the sign-in.

- Deleting a user who created an OAuth2 client failed, because the
  client's creator reference could not be cleared. It is now cleared and
  the client is kept (migration 0070).
- Deleting a user who had created a SAML identity provider, service
  provider, domain binding or similar record failed for the same reason.
  The creator reference is now cleared and the record is kept
  (migration 0077).
- **Email Addresses** in User Settings (`/account/emails`) returned a server
  error for users without an admin role.
- A registered client's own configuration update returned `subject_type` to
  `public` even when an admin had set the app to pairwise subjects. The
  admin's setting is now kept.

- `GET /api/v1/oauth2/clients` reported `oidc_enabled` and
  `available_to_all` as `false` for every client. It now returns the stored
  values, as the single-client endpoint does.
- **SAML sign-ins with two-step verification could not use Single Logout.**
  When a SAML IdP required WeftID two-step verification, the session lost the
  IdP details Single Logout needs, so signing out never reached the IdP.
  They now survive the verification step.
- **SAML IdP single sign-on ignored stale sessions.** The SAML IdP endpoints
  (SSO request, consent, and app launch) read the signed-in user from the
  session without the checks every other page runs, so a session past the
  tenant's maximum session length, of a deactivated user, or of a user who
  must reset their password could still complete a SAML sign-in to a service
  provider. They now apply the same checks, including server-side
  revocation.
- **CSRF protection was never enforced.** The CSRF middleware was registered
  on the wrong side of the session middleware, so it ran before the session
  was decoded and, finding none, allowed every request. Every session-cookie
  form POST in the app (logout, account settings, admin mutations, the OAuth2
  consent decision) was unprotected since CSRF was introduced. The middleware
  now runs inside the session and body-limit layers, and a request with no
  session in scope is rejected instead of allowed. API routes and the SAML
  and OAuth2 protocol endpoints remain exempt as before, and the inbound SCIM
  receiver (bearer-authenticated by the IdP) is now exempt too; correctly
  built forms and `WeftUtils.apiFetch()` calls are unaffected.

### Changed

- **Signing out ends the session on the server.** Sessions are signed
  cookies; until now, signing out only cleared the cookie in the browser, so
  a copy of it kept working until it expired. Every sign-out (the sign-out
  button, the OIDC end session endpoint, a forced re-authentication, the
  SAML consent page's switch account, and SP-initiated SAML logout) now
  revokes the session server-side, and a revoked session is refused on its
  next request. The switch-account and SP-initiated logout paths also notify
  downstream OIDC apps (back-channel) and revoke their session refresh
  tokens, like the sign-out button.
- **BREAKING: SAML Single Logout messages are signed and verified.** WeftID now signs
  the logout requests and responses it sends to SAML identity providers, and
  refuses unsigned logout requests from them (SAML Profiles 4.4.4.1). An IdP
  that sends unsigned logout requests must be configured to sign them.
  Signing out through the OIDC end session endpoint now also starts Single
  Logout at the upstream SAML IdP, as the sign-out button does.
- **BREAKING: OAuth2 / OIDC provider behaviour changes that relying parties may notice.**
  These make the provider pass the OpenID Foundation conformance suite's
  Basic, Config, and Form Post OP plans.
  - Token endpoint errors are RFC 6749 JSON objects with top-level `error`
    and `error_description`, no longer wrapped in `{"detail": {...}}`.
    `invalid_client` is now HTTP 401 with `WWW-Authenticate: Basic`, and a
    malformed token request is `invalid_request` instead of a 422.
  - Token responses omit absent fields (`refresh_token`, `id_token`) instead
    of sending `null`, and carry `Cache-Control: no-store` and
    `Pragma: no-cache`.
  - **Refresh tokens rotate.** The refresh grant returns a new refresh token
    and the presented one stops working. The grant's original 30-day expiry
    is kept. Apps must store the new refresh token after every refresh.
  - **Signing out revokes OIDC refresh tokens.** A refresh token issued
    together with an ID token is tied to the user's WeftID session, and it
    stops working when that session ends (sign-out, the end session
    endpoint, or a forced re-authentication), along with the access tokens
    minted from it. Plain OAuth2 refresh tokens (no `openid` scope) are
    unaffected. The `user_signed_out` audit event records
    `refresh_tokens_revoked`.
  - **The ID token carries only envelope claims** (`sub`, `iss`, `aud`,
    `exp`, `iat`, `auth_time`, `nonce`). The `profile`, `email`, and
    `groups` claims come from the UserInfo endpoint, as OpenID Connect Core
    section 5.4 defines for the code flow. Apps that read `email` or
    `groups` from the ID token must call UserInfo (most OIDC libraries do).
  - The authorization endpoint validates `client_id` and `redirect_uri`
    before anything else, accepts `POST`, requires `response_type`, and
    honours `prompt` (`none`, `login`, `consent`, `select_account`),
    `max_age`, `login_hint`, and `id_token_hint`. `prompt=login` and an
    expired `max_age` require a full local sign-in, which the user first
    confirms on a "Sign in again?" page (cancelling returns `access_denied`),
    so a link on another site cannot sign anyone out. The `claims` parameter
    is not supported, and discovery says `claims_parameter_supported: false`.
- **Anonymizing a user revokes their OAuth2 tokens and remembered consents**,
  as deactivation already did. Anonymization deactivates the user, but their
  tokens used to stay valid until they expired.
- IdP groups can be sourced from an OIDC connection as well as a SAML
  identity provider (new `groups.oidc_connection_id` column, migration 0060).
  Group views show the connection name as the group's source, and IdP group
  audit events carry an `idp_source` of `saml` or `oidc`.
- Expired OAuth2 access and refresh tokens are deleted by the daily cleanup
  job a day after they expire, instead of being kept forever
  (migration 0078).
- A registered client's configuration update can no longer add the device
  grant or drop pushed authorization requests an admin required.

### Security

- **Outbound fetches are harder to abuse.** The SSRF guard now refuses any
  address that is not globally routable, including IPv6 `::` and IPv4 targets
  reached through NAT64, 6to4 or Teredo addresses. Fetches of request objects,
  client JWKS and sector identifier documents have a 10-second overall limit,
  so a server that drips its response can no longer hold a worker for hours.
- The device authorization endpoint and the client configuration endpoint
  (RFC 7592) are rate-limited per client IP, and device codes are hashed with
  SHA-256 instead of Argon2 (they are short-lived 256-bit random values).
- A `private_key_jwt` assertion's `jti` is remembered through the clock-skew
  leeway, closing a 60-second replay window. A dynamically registered pairwise
  client with the device grant must supply a `sector_identifier_uri`. A logout
  token is no longer accepted as an `id_token_hint`.
- **Failed client-secret authentication is throttled.** The token,
  introspection, revocation and PAR endpoints allow 30 failed client-secret
  attempts per minute per client IP, then answer `429` with `Retry-After`.
  Successful authentications are not counted.
- **Slow or oversized responses no longer hold workers.** Fetches from
  upstream OIDC providers (discovery, signing keys, token exchange, UserInfo)
  have a 20-second overall limit and a 1 MiB response cap. Back-channel
  logout deliveries and SAML back-channel logout requests have a 10-second
  overall limit. A failing client URL (`request_uri`, `jwks_uri`, sector
  identifier) is not refetched for 30 seconds, and concurrent fetches per
  client are capped.
- **Registered URIs must have a plain host.** Redirect, logo, logout, JWKS,
  sector identifier and request URIs with userinfo, an invalid port or a
  malformed host are refused, and the Content Security Policy sources built
  from registered URIs are reduced to a plain origin.
- A session that began before this release gets a session ID on its next
  request, so signing out revokes it on the server like any newer session.
- Updated PyJWT to 2.15.1 (13 advisories, including algorithm confusion when
  symmetric and asymmetric algorithms share one verification path, and JWKS
  fetches following redirects) and urllib3 to 2.8.0 (3 advisories).

## [1.12.0] - 2026-09-13

### Added

- **OIDC upstream identity providers.** WeftID can now consume OpenID Connect
  providers as upstream IdPs, alongside the existing SAML 2.0 support. Generic,
  Google Workspace, and Microsoft Entra ID presets are included. The connector
  uses the authorization code flow with PKCE only, validates ID tokens against
  the provider's JWKS, and correlates users on a stable subject claim per
  connection so an upstream email change does not create a duplicate account.
- Admin surface at **Identity Providers > OIDC**: connection list,
  create and edit forms with a provider preset picker, details, claim mapping
  and danger tabs, and a test-connection action that runs real discovery.
- `/api/v1/oidc-upstream/connections` endpoints for listing, creating, reading,
  updating, deleting, enabling, disabling, and setting the default connection.
- Per-connection claim mapping onto WeftID's standard user attributes, mirrored
  on each sign-in subject to the tenant's attribute settings.
- OIDC connections can be bound to privileged domains, so a domain routes its
  users to an OIDC provider exactly as it can to a SAML IdP. A domain still
  binds to at most one IdP across both protocols.
- Per-user disconnect from a connection, scrubbing mirrored attribute values
  that still match what the provider supplied.
- Optional per-connection `require_platform_mfa`, so WeftID's own two-step
  verification can be required after the upstream provider authenticates.
- Providers without a discovery document can be configured from the admin UI:
  the create form has an "Advanced: manual endpoints" section for the Generic
  preset, and the details tab has an Endpoints editor. Manual endpoints must be
  HTTPS, enforced by the same rule in the UI and the API.
- Documentation: [OIDC Setup](docs/admin-guide/identity-providers/oidc-setup.md)
  plus Google Workspace and Entra ID walkthroughs, and glossary entries for OIDC
  discovery, JWKS, the UserInfo endpoint, and correlation claims.
- The OAuth2 token endpoint accepts `client_secret_basic` (HTTP Basic) client
  authentication in addition to `client_secret_post` form fields, as RFC 6749
  requires. The discovery document now advertises
  `token_endpoint_auth_methods_supported`.
- Upstream OIDC browser E2E test: WeftID's own OpenID Provider acts as the
  upstream IdP for a second tenant (`tests/e2e/test_oidc_upstream_loopback_e2e.py`,
  provisioned by `app/dev/oidc_loopback_testbed.py`). Covers JIT provisioning on
  first sign-in and subject correlation on the second.
- Hourly worker job that purges expired forward-auth handshake nonces.
  Abandoned handshakes previously left their rows in the database
  indefinitely.

### Changed

- **Admin navigation restructured around concepts, not permissions.** The
  `Admin` top-level wrapper is gone; the sections it held are now top-level
  nav items, and a few pages were regrouped or renamed to match. Old URLs
  still work: every path below issues a permanent (301) redirect to its new
  location. Per-instance detail URLs redirect too: the ID and any sub-tab
  after the old prefix are preserved, and the query string survives the hop.

  | Old path | New path |
  |----------|----------|
  | `/admin/groups*` | `/groups*` |
  | `/admin/todo*` (renamed **Requests**) | `/directory/requests*` |
  | `/admin/settings/user-attributes` | `/directory/attributes` |
  | `/admin/audit/user-export` | `/directory/exports` |
  | `/admin/settings/identity-providers*` | `/identity-providers/saml*` |
  | `/admin/settings/oidc-identity-providers*` | `/identity-providers/oidc*` |
  | `/admin/settings/privileged-domains` (renamed **Domain Routing**) | `/identity-providers/domain-routing` |
  | `/admin/settings/service-providers*` | `/applications/saml*` |
  | `/admin/integrations/apps` (renamed **OAuth2 / OIDC**) | `/applications/oauth` |
  | `/admin/settings/protected-domains*` + `/admin/settings/proxy-apps*` (merged as tabs) | `/applications/forward-auth/domains*` / `/applications/forward-auth/apps*` |
  | `/admin/integrations/b2b` (renamed **Service Accounts**) | `/applications/service-accounts` |
  | `/admin/settings/security*` | `/security*` |
  | `/admin/audit/events*` | `/audit/events*` |
  | `/admin/audit/saml-debug*` | `/audit/saml-debug*` |
  | `/admin/settings/branding*` | `/settings/branding*` |
  | `/admin/settings/about` | `/settings/about` |
  | `/admin`, `/admin/` | `/dashboard` |

  SAML and OIDC identity providers now render as sibling tabs under
  **Identity Providers** instead of two unrelated sections. Protected Domains
  and Proxy Apps are now **Domains** and **Apps** tabs under
  **Applications > Forward Auth**. `/users*` is unaffected (only its nav
  grouping changed, under **Directory**). All existing permission levels are
  unchanged; only navigation location moved.
- `determine_auth_route` and `AuthRouteResult` moved to protocol-neutral homes
  (`services.auth_routing`, `schemas.auth_routing`) now that login routing
  resolves OIDC connections as well as SAML IdPs. The previous
  `services.saml.routing` import continues to work.
- The Directory requests badge count is cached per tenant for 30 seconds and
  invalidated when a request is approved, denied, or force-completed, instead
  of running two uncached counts on every page render.
- Updated runtime dependencies (starlette 1.6.0, pydantic 2.13.5,
  argon2-cffi-bindings 26.1.0, cairosvg 2.9.1).

### Fixed

- Signing in through an identity provider from the login page did not work in
  Chromium: the email step's redirect chain was cut off by the page's CSP
  `form-action` at the off-origin hop, for SAML and OIDC alike. The email step
  now renders a same-origin hand-off page that navigates to the provider.
- The OAuth2 consent page could not complete for relying parties on another
  origin in Chromium, for the same reason. The consent page now allows the
  registered redirect URI's origin in its CSP, as the SAML IdP does for SP ACS
  URLs.
- Upstream OIDC discovery, JWKS, token, and userinfo fetches now use the SSRF
  guard's dev-only base-domain rewrite so a dev-stack tenant can be its own
  upstream IdP. No production behavior change.
- Downloading a historical user export returned a 500 when the configured
  storage backend no longer matched the backend the export was written to.
  It now returns a 404 with a clear message.

### Security

- Upstream client secrets are encrypted at rest with a purpose-specific Fernet
  key and are never returned from any read path.
- All outbound requests to a provider (discovery, token exchange, userinfo,
  JWKS) go through the SSRF-hardened HTTP client. Discovery documents are
  rejected when the issuer does not match the configured issuer or when any
  endpoint is not HTTPS.
- Linking an upstream subject to an existing WeftID account by email address is
  off by default. When enabled it additionally requires the ID token to assert
  `email_verified`.
- An admin could deactivate or reactivate a super-admin-tier B2B service
  account through the Applications routes, bypassing the super admin
  boundary. The edit, deactivate, and reactivate handlers now reject
  non-normal client types, matching the sibling handlers.
- The Directory router is mounted behind the admin requirement again, with
  the authenticated index redirect split into its own router. Previously
  each handler carried its own admin check, so a future handler that forgot
  it would have been reachable by regular users without the compliance
  checker noticing.
- Updated httpx2 and httpcore2 to 2.12.0 to address CVE-2026-84379,
  CVE-2026-84380, CVE-2026-84381, and CVE-2026-84382. These are development
  dependencies (test client) and are not in the production image.

## [1.11.1] - 2026-08-30

### Security

- Hardened redirect handling: every same-origin redirect built from request
  data now passes through a single `safe_redirect()` validation point that
  rejects protocol-relative, scheme-carrying, backslash, and control-character
  targets, closing off open-redirect and response-splitting. A compliance check
  now enforces the rule so new routes cannot regress it.
- Updated cryptography to 50.0.0 and pyopenssl to 26.4.0 to address CVE fixes.
- Updated pillow to 12.3.0 and pyasn1 to 0.6.4 to address CVE fixes.
- Updated pip to 26.2.1 to address CVE-2026-13346.

### Fixed

- Fixed a bug where a "&" or "#" in a group member search term could add or
  truncate query parameters on the add-members redirect, and a backslash could
  drop the admin on the dashboard instead of the membership page. Redirect
  query values are now percent-encoded.

### Changed

- Updated runtime dependencies (webauthn 3.0.0, msoffcrypto-tool 6.0.0, cbor2
  6.1.4, ua-parser-builtins).

## [1.11.0] - 2026-07-12

### Added

- **Sign in with WeftID (OIDC provider).** WeftID is now a spec-correct
  downstream OpenID Provider, layered additively on the existing OAuth2
  authorization-code flow. An OIDC-enabled app receives a signed RS256 ID token
  (gated on the `openid` scope) alongside the usual access/refresh tokens, plus a
  per-tenant discovery document (`/.well-known/openid-configuration`), published
  signing keys (`/.well-known/jwks.json`), and a `/userinfo` endpoint. Released
  claims are gated by the scopes the app requests (`openid`, `profile`, `email`,
  `groups`), with DAG-aware effective group memberships in the `groups` claim.
  Access uses the same group-based model as SAML service providers and
  forward-auth apps: users without a grant are denied at the authorize step
  before any code is issued. Managed from the admin UI and under
  `/api/v1/oauth2/clients/{client_id}` (enable OIDC, access mode, group
  assignments) and `/api/v1/oidc/signing-key` (inspect, rotate, and clean up the
  per-tenant RSA key, with a configurable JWKS overlap window and an automatic
  sweep of retired keys). See the new "Sign in with WeftID (OIDC)" admin guide.

### Changed

- Upgraded the application runtime to Python 3.14.
- Normalized file permissions across the app tree in the production Docker image.
- Renamed the deactivated-client status badge from "Inactive" to "Deactivated"
  to match the rest of the lifecycle terminology.
- Updated bundled runtime dependencies (pydantic 2.13.4, anyio 4.14.1, uvloop
  0.22.1) and the documentation-site build toolchain (pygments 2.20.0,
  pymdown-extensions 11.0.1). uvloop 0.22.1 is the first release with prebuilt
  wheels for Python 3.14, which the runtime upgrade requires.

### Fixed

- Fixed four periodic worker sweeps (service-provider and per-IdP certificate
  rotation/cleanup, SAML metadata refresh, and idle-user auto-inactivation) that
  silently returned no rows and never ran in deployments using the RLS-enforcing
  `appuser` connection. These background jobs now run as intended.

### Security

- Fixed a pre-authentication denial-of-service on the OAuth2/OIDC token, refresh,
  and `/userinfo` endpoints, where a presented bearer token or authorization code
  was verified against every live credential in the tenant (one Argon2 hash per
  credential). Validation now resolves a single row via an indexed lookup and
  verifies exactly once. (A07:2021)
- Fixed OIDC access-revocation lag: removing a user's group access (or narrowing
  an app from available-to-all) now immediately revokes their outstanding tokens,
  and the refresh-token grant re-checks access, so a revoked user can no longer
  mint new access tokens for the remaining lifetime of the refresh token.
  (A01:2021)
- Stopped the OAuth2/OIDC authorize flow from rendering a consent page or issuing
  an authorization code for a deactivated client. (A01:2021)
- Fixed a cross-tenant injection in SAML service-provider bulk group assignment,
  where an unvalidated group id could create a grant referencing another tenant's
  group. (A01:2021)
- Stopped the passkey registration endpoint from returning raw exception text to
  the caller. A rejected payload was answered with the exception's message in a
  `details` field, and the surrounding `except` was broad enough that an
  unexpected internal error would have its message disclosed too. Present since
  1.5.0. (A05:2021)

## [1.10.0] - 2026-06-23

### Added

- **Forward-auth reverse-proxy SSO.** WeftID can now protect arbitrary HTTP
  applications that have no native SAML/OIDC support, by acting as a forward-auth
  provider for a reverse proxy (Traefik, nginx, Caddy). Tenants register a domain,
  prove control via a DNS-TXT challenge, then register proxy apps under that domain
  and grant access by group (reusing the existing group-based access model, DAG-aware).
  The proxy delegates each request to WeftID's `/check` endpoint; unauthenticated
  users are sent through a single-use-token handshake that sets a signed, per-domain,
  1-hour HttpOnly cookie, and authenticated identity is forwarded to the app via
  `X-Forwarded-*` headers. Proxy apps appear in the My Apps dashboard and `/my-apps`
  API alongside SAML apps. Ships with an admin-guide page (proxy configs, on-demand
  TLS, cookie stripping, troubleshooting) and a Caddyfile catch-all for protected-domain
  portal hosts.

### Changed

- Self-edited user attributes are no longer emitted in signed SAML assertions by
  default. Attributes now carry a provenance source (`idp`, `admin`, or `self`);
  `self`-sourced values are withheld from downstream SPs unless the tenant opts the
  attribute in via a new per-attribute toggle. This prevents a non-admin from
  self-asserting values (department, employee_id, and others) that an SP would otherwise
  trust as IdP/admin-grade. An upgrade backfill classifies existing rows as `idp` or
  `admin`, so values currently flowing are unchanged. Note for SP operators: future
  self-edits will not propagate to SPs unless you enable the per-attribute toggle.
- IdP-mirrored attributes are scrubbed by default when a user is disconnected from an
  identity provider. Reassigning a user to password auth or a different IdP now clears
  canonical attribute values that still match the old IdP's mirror snapshot (admin and
  user-edited values are kept), instead of emitting stale departed-IdP values in signed
  assertions indefinitely. The scrub is default-on with an opt-out at every boundary
  (disconnect form, IdP-delete tab, API). Existing assignments are not affected.

### Security

- Closed an SSRF (DNS-rebinding) window on admin-supplied outbound URLs (SCIM target
  URL, SP SLO URL). These were validated for private/reserved IPs only at save time,
  then re-resolved and dialed later with no re-check. Outbound HTTP now resolves each
  target once and dials that exact IP, eliminating the resolve-then-connect gap.
- Fixed Row-Level Security policies so UNSCOPED writes to tenant-isolation-widened
  tables fail closed. A permissive "tenant unset implies allow" branch remained in the
  WITH CHECK clause, which could in principle let an UNSCOPED INSERT/UPDATE write an
  arbitrary tenant_id (latent: all UNSCOPED paths were read/DELETE-only).
- Hardened defense-in-depth across inbound SCIM (bearer-length cap before pre-auth hash,
  bounded members array), forward-auth (reject bare public suffixes as protected domains,
  assert token/cookie format version), and fixed several audit-log gaps (SCIM
  reactivation events, WebAuthn admin token-revoke attribution, domain verification
  failures, no-op settings PATCH no longer logging).
- Updated cryptography, python-multipart, pip, msgpack, and starlette to clear known CVEs.

## [1.9.0] - 2026-06-13

### Added

- **Inbound SCIM provisioning.** WeftID can now act as a SCIM 2.0 receiver, letting an
  upstream identity provider (Okta, Entra ID, and others) create, update, and deactivate
  users and groups in WeftID in real time, so deprovisioned users lose access immediately
  instead of at their next sign-in. Each identity provider gets a **SCIM Provisioning** tab
  with a SCIM base URL and bearer-token management (tokens are shown once and stored hashed,
  with no rotation/recovery path). Provisioned changes are replayed to downstream
  SCIM-enabled service providers, and cross-IdP rebinds are handled. Setup guides for Okta
  and Entra are included.
- Admin email notification when the daily idle-user job deactivates accounts, listing the
  affected users (name, email, last activity) and the configured inactivity threshold.

### Changed

- Renamed the user lifecycle action and state from "Inactivated" to "Deactivated" across the
  UI and documentation, reserving "inactive"/"inactivity" for the idle condition that can
  lead to deactivation. Stored status values are unchanged.
- WeftID now trusts the reverse proxy's forwarded client IP and scheme (configurable via
  `FORWARDED_ALLOW_IPS`, default `*`), so per-IP rate limits (login, SCIM auth, and others)
  see the real client address instead of the proxy's. Self-hosters using the bundled
  nginx/Caddy setup need no action.

## [1.8.0] - 2026-05-23

### Fixed

- **Outbound SCIM group membership no longer silently drops members at spec-compliant receivers.** WeftID was using its own UUID as the SCIM `id` in `Group.members[].value` and in PUT/PATCH/DELETE paths. Receivers that mint their own server-assigned `id` per RFC 7644 §3.3 (Authentik, most spec-compliant SCIM 2.0 sources) resolve group members against that server id, so the WeftID-UUID references never matched and members landed in zero groups downstream. The worker now captures the receiver's `id` from the first POST response, stores it in a new mapping table, and uses it for every subsequent PUT/PATCH/DELETE and for group member references. Affects any tenant whose downstream SCIM receiver does not happen to conflate `id` with `externalId`
- **404 on `DELETE /Users/<id>` or `DELETE /Groups/<id>` no longer dead-letters.** Removing a group grant for users the receiver never saw used to flood the sync log with false failures. The Generic adapter now treats 404 on DELETE as success-like ("resource is already gone"), drains the queue row, and surfaces the outcome as an amber **Skipped** badge in the Sync activity panel. 404 on POST/PUT/PATCH continues to behave as before
- **404 on PUT against a stale id self-heals.** If a downstream resource is recreated (or our recorded id otherwise drifts), the next push gets a 404, WeftID clears the stale mapping, and the attempt after that POSTs cleanly to remint the mapping. No operator intervention required

### Changed

- The Atlassian quirk's "404 is permanent (already gone)" override was removed in favor of the new general policy (404 on DELETE = success, 404 on other verbs = permanent). Behavior is unchanged for the common deprovisioning case
- GitHub Enterprise Cloud's SCIM quirk opts out of PUT-on-Groups (GitHub returns 405) via a new per-vendor `GROUP_UPDATE_VERB` capability flag. Behavior for GitHub tenants is preserved: groups still go through POST only, with the same 409-on-duplicate semantics as before

### Added

- New `sp_scim_remote_ids` table (tenant-scoped with RLS) records WeftID-id → receiver-id mappings. Migration `0041_scim_remote_ids.sql` is purely additive and applied automatically on self-hosted upgrades. Rows that pre-date the table self-heal on the next push via a fallback path; no resync action is required
- New audit events `scim_remote_id_mapped` (first time a receiver mints an id for a resource) and `scim_remote_id_invalidated` (a 404 cleared a stale mapping). Both are operational tier, visible in the audit log when operational events are shown
- The SCIM admin guide gained a "Resource ID mapping" section explaining when mappings are created, used, and cleared, plus updated status meanings (the new amber **Skipped** badge) and worker reason codes (`already_absent`, `remote_id_invalidated`)
- New `dev/scim-testbed.sh` bootstrap script (and `make scim-testbed-{up,down,destroy,status,logs,info}` targets) spins up a local Authentik instance for end-to-end outbound-SCIM testing. The Authentik runtime lives outside the WeftID checkout by default (`~/.local/share/weft-id/scim-testbed/authentik/`) so generated secrets and volumes can't leak into source. See `dev/scim-testbed.md`. Authentik is a separate MIT-licensed project; WeftID does not bundle or redistribute it
- Dev-only: `host.docker.internal` is allowed as a SCIM target URL when `IS_DEV=true`, so WeftID's containers can reach a SCIM receiver running on the Docker Desktop host. Production builds reject it as before

## [1.7.1] - 2026-05-23

### Added

- Outbound SCIM credentials can now be **imported** from the downstream application in addition to being generated by WeftID. Use the new **Import existing token** button on the SP's SCIM tab for receivers that mint the bearer token on their side (e.g. Authentik, some self-hosted SCIM servers). Generated and imported tokens are stored and pushed identically; only the source differs
- New additive `POST /api/v1/service-providers/{sp_id}/scim/credentials/import` endpoint (super_admin, shares the 10/min rate-limit bucket with the existing `POST /scim/credentials` mint endpoint) and a distinct `scim_token_imported` audit event so imported credentials are auditable separately from generated ones

## [1.7.0] - 2026-05-23

### Added

- Outbound SCIM 2.0 provisioning: WeftID can now push user and group changes to downstream applications, closing the gap that pure SAML cannot (a user removed from WeftID no longer retains access to downstream SaaS)
- SCIM 2.0 push client with per-vendor quirk modules: day-one support for **Slack** (Enterprise Grid), **GitHub Enterprise Cloud**, **Atlassian** (Guard / Access), and **GitLab.com**; a spec-correct **Generic SCIM 2.0** path covers everything else
- Admin UI under each SP's **SCIM** tab: target URL, application type, group membership mode (effective / direct), sync activity retention (3 / 6 / 12 / 24 months / forever), and bearer-credential management
- Bearer-credential lifecycle: tokens minted by WeftID, displayed in plaintext exactly once, Fernet-encrypted at rest; **rotation** with a 24-hour overlap window so in-flight pushes complete cleanly; instant **revoke**
- Sync activity panel: live pending and dead-lettered counters, per-status filtering, and a "Retry dead-lettered" action that re-enqueues every dead row for the SP
- Per-tenant background worker with retry, exponential backoff, dead-letter on retry-budget exhaustion, and per-SP sequential fan-out within a tenant slice to avoid hammering a single downstream
- Event-log-driven dispatch: mutations tagged with a `scim_trigger` annotation in the event-type registry enqueue work automatically; eager fan-out at trigger time for group / membership changes so queue depth is a meaningful "work remaining" metric
- Coalescing outbox keyed `UNIQUE(sp_id, resource_type, resource_id)`: re-enqueues bump `enqueued_at` and reset attempts; the worker re-fetches current resource state at push time so "last state wins" is automatic and deprovision is just "user no longer in scope"
- Two-log model: admin actions (token create / rotate / revoke, config edits) go to the main audit log with indefinite retention; per-push outcomes go to a dedicated `scim_sync_log` with per-SP retention (default 3 months, configurable to 6 / 12 / 24 months or **forever** for regulated tenants)
- API endpoints under `/api/v1/service-providers/{sp_id}/scim`: config GET/PUT, credentials CRUD, sync-log paginated read, queue status, and retry-dead-lettered POST
- Documentation: full admin guide at `docs/admin-guide/service-providers/scim.md` with per-vendor walkthroughs (Slack / GitHub / Atlassian / GitLab), credential lifecycle, sync panel reference, and a troubleshooting section
- Inline help link from the SP detail SCIM tab to the docs page

### Fixed

- OAuth2 authorization endpoint: `auth_request_id` single-use replay protection now works correctly under Starlette 1.0+. The previous nested-mutation pattern silently failed to mark the session modified, so a reused `auth_request_id` could redirect with a fresh code instead of showing the error page

### Security

- Bumped `starlette` to 1.0.1 (PYSEC-2026-161 / GHSA-86qp-5c8j-p5mr: Host header URL reconstruction)
- Bumped `fastapi` to 0.136.1, `python-multipart` to 0.0.29, `psycopg-pool` to 3.3.1, `ua-parser` to 1.0.2, and refreshed `idna` to 3.15 in production requirements

## [1.6.0] - 2026-05-15

### Added

- Standard user attributes: a 14-attribute registry (contact, professional, location, profile categories) with per-tenant configuration for enable/required/mirror-from-IdP/locked-for-users/send-to-SPs flags
- Tenant attribute configuration settings page (`/admin/settings/user-attributes`) with per-row toggles and category bulk enable/disable
- Self-service profile attribute editing on the user profile page and admin attribute editing on the user detail tab, grouped by category
- Admin-only "Connected IdP attributes" panel showing the per-IdP mirror snapshot for each user
- IdP-driven attribute mirroring: SAML logins extract registry-keyed values via the per-IdP attribute mapping and mirror them into canonical user profiles
- Downstream SAML assertion emission for enabled tenant attributes, with a per-SP "available, not sent" view and per-row SAML OID toggle in the admin attribute tab
- Tenant-required attribute enforcement: dashboard banner for missing user-fixable fields, Admin Todo view listing every user with any missing required attribute, and a bulk force-profile-completion action that gates navigation until missing unlocked-required fields are filled
- Opt-in scrub of mirrored attributes when disconnecting an IdP: web checkbox on the danger tab and `?scrub_mirrored_attributes=true` on the DELETE API. Diverged values are preserved
- API endpoints: `GET/PUT /api/v1/tenant/attribute-config`, `/api/v1/users/{id}/attributes`, and `/api/v1/me/attributes` for canonical and IdP-mirror reads/writes
- Audit events: `user_idp_attribute_mirror_failed` (admin tier) and `tenant_attribute_config_read_failed` for visibility into mirror-write and config-read failures during SSO

### Changed

- Per-IdP `attribute_mapping` now accepts registry keys (jobTitle, phoneWork, etc.) alongside the existing fixed email/first_name/last_name/groups
- New SPs are seeded with the tenant's default sendable attribute set; existing SPs are untouched
- `mirror_from_idp` defaults to true on newly-enabled attributes so enabling an attribute does the obvious thing; tenants who want IdP values held only as read-only diagnostic info can turn the flag off
- `user_profile_updated` event metadata now records an action per key (added/updated/cleared) instead of `{old, new}` values, keeping phone/mobile/address/postal-code/employee-ID values out of the event stream
- Copy: unified "Profile attributes" naming, softer forced-mode banner, clarified flag tooltips, "Send to new SPs" replaces "Send to SPs by default", and a new docs page for user attributes
- Documentation: scrub-on-disconnect section in the SAML setup guide, expanded audit event-type table, and seven admin/user guide pages updated for the new feature

### Fixed

- Removed the misleading "Enable all in <category>" checkbox on the tenant attribute settings page (it overwrote partial selections)
- Profile attribute save errors and successes now render as flash banners instead of silently appearing in the URL
- Passkey E2E tests no longer race the auto-ceremony redirect on slow runs and leave the shared test tenant with a lingering passkey
- Several pre-release correctness fixes on the user attributes feature (self-edit 403 on non-string user IDs, duplicate `displayName` SAML attribute when SPs had no mapping, stale event-log diffs, RLS-safe set-based mirror scrub)

### Security

- Bumped `cryptography` 46.0.7 → 48.0.0 and `uvicorn` 0.42.0 → 0.47.0
- Bumped `python-multipart`, `pyopenssl`, `certifi`, `urllib3`, and `pip` to clear the dependency CVE backlog
- Removed raw PII (phone, mobile, address, postal code, employee ID) from `user_profile_updated` audit event metadata. The audit signal (who changed which key, when, how) is preserved
- IdP attribute mirror-write failures and tenant attribute config read failures during SSO are now surfaced as admin-tier audit events instead of only container logs

## [1.5.0] - 2026-04-25

### Added

- Passkey authentication (FIDO2/WebAuthn): register, list, rename, and delete passkeys from the two-step verification page
- Passkey login with a scoped ceremony and clone detection on used authenticators
- Admin passkey management: per-user passkey view/revoke and auth-method filter on the user list
- Tenant authentication strength policy with forced TOTP enrollment and platform-MFA requirement
- Passkey enrollment accepted under the enhanced auth policy
- API endpoints for SAML IdP reimport-xml and SAML debug entry retrieval (with response schemas)
- API endpoint to clear all group relationships in one call
- Admin passkey API endpoints (list, revoke)

### Changed

- Renamed "two-step verification" copy where it was inaccurate now that passkeys are available
- Passkey-related copy aligned across templates and emails (revoke terminology, MFA reset docs)
- Tenant auth strength selector switched from a dropdown to radio buttons
- Passkey clone detection raises a typed exception instead of matching error strings

### Fixed

- Enforce `require_platform_mfa` on SAML IdP login (policy was not applied on that path)
- Enhanced auth policy bypass via email OTP closed
- TOCTOU race in passkey `complete_authentication`
- Passkey-existence oracle on the login page (revealed whether a user had a passkey registered)
- Migration `0032` conflict with baseline schema on fresh installs

### Security

- WebAuthn RP ID now derived from the tenant record, not request headers (prevents RP ID spoofing via `Host`/`Origin` manipulation)
- Require user verification (UV) in all WebAuthn ceremonies (registration, authentication, reauth)
- Bounded request body size and tightened WebAuthn input schemas
- Rate limits on passkey registration and enrollment endpoints
- Plain admins can no longer revoke super_admin passkeys (privilege escalation blocked)
- Updated `lxml` and `python-multipart` to fix CVEs
- Minor dependency bumps: `click`, `werkzeug`, `python-dotenv`, `ua-parser-builtins`, `watchfiles`

## [1.4.1] - 2026-04-13

### Security

- Updated Pillow to 12.2.0 to fix GZIP decompression bomb vulnerability
- Updated pytest to 9.0.3 to fix insecure tmpdir handling

## [1.4.0] - 2026-04-13

### Added

- SAML assertion debug log for troubleshooting authentication failures, accessible at **Audit > SAML Debug** with optional verbose logging for successful assertions
- SAML assertion replay prevention via Memcached (each assertion ID is cached and rejected on resubmission within its validity window)
- SAML assertion attribute resilience: missing optional attributes (first name, last name) no longer block sign-in. Existing user values are preserved.
- Automatic user attribute sync from the upstream IdP on each SAML sign-in (first name, last name updated when they differ)
- Failed SAML authentication attempts are now always logged with full diagnostic details
- SLO URL editing for metadata-imported service providers (previously read-only)

### Changed

- IdP-assigned users skip the password-setting step during onboarding and are directed to sign in through their identity provider
- SAML Debug Log moved from Settings to the Audit section in navigation
- Profile editing policy (`allow_users_edit_profile`) now enforced in the service layer, covering both web UI and API

### Security

- Added `max_length` constraints to all `Form()` parameters to prevent oversized input attacks (e.g., CPU exhaustion via Argon2 with megabyte-length passwords)
- Fixed XSS in assertion attribute preview where user-controlled data was interpolated via innerHTML without escaping
- Blocked SSRF via redirect following in SAML metadata URL fetch
- Fixed open redirect via unvalidated SAML RelayState parameter
- Replaced sequential integer nonces with cryptographically random tokens for email verification and password-reset links
- Removed unauthenticated check-email API endpoint (user enumeration vector)
- Removed super admin self-reactivation bypass; all reactivations now require admin approval
- Restricted B2B OAuth2 client management to super admins (was admin+)
- Rate-limited the account reactivation endpoint
- Certificate rotation grace period bounded to 0-90 days
- PII redacted from verbose SAML assertion event log metadata
- Docker containers now run as a non-root user
- Install script generates a random database password for the application user
- Install script sets `.env` file permissions to 600 (owner-only read/write)
- On-demand TLS certificate issuance restricted to registered tenant subdomains

## [1.3.0] - 2026-04-10

### Added

- Per-SP AES-256-GCM assertion encryption (opt-in) for SAML IdP connections, replacing CBC where enabled
- Auto-download of the Tailwind CSS binary on first use (no manual install required)

### Changed

- Renamed remaining "Loom Identity Platform" references to "WeftID" in X.509 signing certificates and the API schema title
- Role values now display as "Super Admin" / "Admin" / "User" instead of raw database values across all templates
- Consolidated repo root: moved compose files, shell scripts, and project management files into dedicated directories; retired shell scripts in favor of `make` targets

### Security

- Fixed CBC padding oracle vulnerability on SAML ACS endpoints
- Scoped the SAML ACS rate limit key per tenant to prevent cross-tenant denial-of-service via shared egress IPs
- Updated cryptography from 46.0.6 to 46.0.7

## [1.2.0] - 2026-04-05

### Added

- Streamlined sign-in flow that routes directly to auth method without email verification, with tenant opt-in setting to preserve the old discovery flow
- Bulk user operations from the user list: inactivate/reactivate, add to group, add secondary emails, and change primary email with dry-run SP assertion impact preview
- User audit export as password-encrypted XLSX (Users, Group Memberships, App Access sheets)
- Audit log XLSX export with optional date range, replacing the JSON export
- Audit event visibility tiers (security, admin, operational, system) with color-coded UI toggles and API filter support
- Resend invitation email for pending users with nonce-based link invalidation
- Branded email headers with tenant logo and name across all 15 outbound emails, plus a Pageloom footer
- User list filter panel redesigned as floating popover with IS/IS NOT toggle, filter negation, group hierarchy inclusion, and tinted active-state borders
- Contextual documentation links on admin pages (information-circle icon linking to relevant docs)
- Icons on action bar buttons

### Changed

- Email management is now admin-only; self-service email add/remove/promote/verify removed from user accounts
- Sign-in flow defaults to skipping email verification (old behavior available via `require_email_verification_for_login` tenant setting)
- Consolidated tenant name and site title into a single field (`tenants.name`)
- Standardized product name to "WeftID" across all user-facing copy
- Renamed "MFA" to "two-step verification" in emails and exports
- Authorization denial logs moved from tenant audit trail to application logs
- Removed `weftid` management script in favor of documented Docker Compose commands

### Fixed

- Fixed XSS in bulk email template where user-controlled names were interpolated via innerHTML
- Fixed group picker missing group_type data and modal backdrop issues
- Fixed export file passwords persisting in the database after file expiry (now redacted)
- Fixed flaky test_claim_next_task in parallel test runs

### Security

- Set-password and invitation links are now one-time use via nonce-based invalidation (migration 0023)
- Bounded bulk operation list fields to max 5000 items to prevent resource exhaustion
- Export file passwords are redacted from the database after the download window expires

## [1.1.0] - 2026-03-21

### Added

- Group assertion scope setting to control which groups are shared in SAML assertions (access-relevant, trunk, or all) with per-SP override and consent screen disclosure
- Email deliverability verification CLI (`python -m app.cli.verify_email`) for checking SPF, DKIM, and DMARC before tenant provisioning
- Self-hosting upgrade and backup documentation with full rollback procedure

### Changed

- Restructured self-hosting guide as a numbered first-setup flow with install directory guidance
- Self-hosting docs now emphasize that SECRET_KEY and POSTGRES_PASSWORD are irrecoverable
- Standardized password error messages across all password templates
- Rebuilt documentation site with Zensical 0.0.28

### Fixed

- Fixed production Docker image showing "dev" as the version when the build arg was not explicitly passed
- Fixed incorrect role list in self-hosting backup documentation (removed unused migrator role)

### Security

- Fixed LIKE wildcard injection in search queries where %, _, and \ in search terms were interpreted as SQL wildcards instead of matching literally
- Added rate limiting to password change endpoints (5 per user per hour, 10 per IP per hour)
- Fixed content injection via unvalidated query parameters in password-related templates

## [1.0.4] - 2026-03-21

### Added

- About WeftID page in admin settings showing the running version, documentation links, and project info
- API endpoint at `/api/v1/settings/version` for retrieving version information
- Documentation for password policy settings, HIBP breach detection, forced password reset, and self-service password flows

### Changed

- Updated group hierarchy documentation with shift+drag subtree move and tooltip positioning details

### Fixed

- Fixed Postgres 18 data loss on container restart caused by a PGDATA path change in Postgres 18
- Fixed version detection in the dev Docker environment when the app directory is bind-mounted

## [1.0.3] - 2026-03-21

### Fixed

- Fixed missing `defusedxml` runtime dependency that could cause import errors in production

## [1.0.2] - 2026-03-21

### Fixed

- Fixed missing `httpx` runtime dependency that could cause import errors in production

## [1.0.1] - 2026-03-21

### Changed

- Replaced Poetry with pip in the production Dockerfile, eliminating ~3 minutes of arm64 cross-compile time under QEMU emulation. A CI workflow now keeps a pinned requirements file in sync with `poetry.lock`.
- Bumped Docker GitHub Actions to latest majors (setup-buildx v4, login v4, metadata v6, build-push v7)
- Bumped uvicorn from 0.41.0 to 0.42.0
- Bumped resend from 2.23.0 to 2.26.0
- Bumped zensical from 0.0.24 to 0.0.28
- Bumped ruff from 0.15.5 to 0.15.7

## [1.0.0] - 2026-03-20

Initial release of WeftID, a multi-tenant identity federation platform.

### Added

**Identity Federation**
- SAML 2.0 identity provider integration (Okta, Entra ID, Google Workspace, generic SAML)
- OAuth2 identity provider support
- Per-connection SAML entity IDs (stable URN-based)
- Domain routing for multi-IdP tenants
- JIT user provisioning from SAML identity providers

**SAML Identity Provider**
- SAML 2.0 Identity Provider for downstream service providers
- SP-initiated SSO with user consent screen
- Per-SP signing certificates with configurable lifetime and auto-rotation
- SAML assertion encryption (IdP-side for downstream SPs, SP-side decryption for upstream)
- Single Logout (SLO) for downstream service providers
- Per-SP NameID format configuration
- Opt-in group claims in SAML assertions with per-SP attribute mapping
- Dynamic attribute declarations in SAML metadata

**Authentication & Security**
- Multi-factor authentication (TOTP with backup codes, admin reset)
- Password strength policy with zxcvbn entropy scoring and HIBP breach checking
- Password lifecycle hardening (expiry, reuse prevention, admin-forced reset)
- Self-service forgot password flow with stateless time-windowed tokens
- Rate limiting on authentication endpoints
- CSRF protection with per-request tokens
- Content Security Policy with script nonces
- HKDF-based key derivation for all cryptographic operations
- Secure session management with configurable timeouts

**User Management**
- User lifecycle management (creation, inactivation, reactivation with approval flow)
- Invitation-based onboarding with email verification
- User profile with dark mode and timezone preferences
- Privileged email domains with automatic group assignment

**Groups**
- Group system with DAG hierarchy (multiple parents, cycle prevention via closure table)
- Group-based service provider access control with "available to all users" mode
- Effective membership queries (direct and inherited)
- Interactive group graph visualization with dagre layout and DB-persisted positions
- IdP-synced groups with umbrella and assertion sub-groups
- Per-group logo upload and customizable acronyms
- Bulk member management

**Service Provider Management**
- Two-step SP registration with trust establishment
- SP lifecycle management (enable, disable, delete)
- SP metadata lifecycle (import, refresh, manual entry)
- SP logo/avatar support
- User access count on SP list view

**Tenant & Branding**
- Multi-tenant data isolation with Row-Level Security
- Tenant branding with custom logo upload and generated mandala fallback
- Custom site title with nav bar visibility toggle

**Audit & Operations**
- Comprehensive audit logging with request metadata
- Activity tracking for read operations
- Data export system with background job processing
- Integration management (API keys with lifecycle controls)

**Infrastructure**
- RESTful API (v1) for all management operations with OAuth2 bearer token auth
- Production Docker Compose with Caddy for automatic HTTPS (on-demand TLS)
- Self-hosting install script with secret generation
- Tenant provisioning CLI
- Forward-only migration system with baseline schema
- Health check endpoint and bare domain rejection
- Documentation site served at /docs
- GitHub Actions CI (lint, format, type check, tests, E2E)
- GHCR publish workflow with multi-arch Docker images (amd64, arm64)
