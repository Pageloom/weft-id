# Single Logout

Single Logout (SLO) ends a user's session across WeftId and their connected applications. When a user signs out, WeftId notifies each application they accessed during the session so those applications can terminate their local sessions too.

SLO is optional. Applications that don't support it simply keep their local session until it expires naturally.

## How it works

WeftId supports SLO in two directions:

- **User signs out of WeftId** -- WeftId sends a LogoutRequest to each application the user accessed during the session. This is best-effort: if an application is unreachable or slow, the sign-out still completes.
- **Application signs out the user** -- The application sends a LogoutRequest to WeftId. WeftId terminates the user's session and returns a LogoutResponse.

Both directions use signed SAML messages. WeftId advertises both HTTP-Redirect and HTTP-POST bindings for its SLO endpoint.

## Configuring SLO

### On a service provider

When [registering a service provider](registering-an-sp.md), set the **SLO URL** field to the application's Single Logout endpoint. This is the URL where WeftId sends LogoutRequests when the user signs out.

If the application's SAML metadata includes a `SingleLogoutService` element, WeftId imports the SLO URL automatically. Otherwise, enter it manually.

Applications without an SLO URL are silently skipped during logout propagation.

### On an identity provider

When [connecting an identity provider](../identity-providers/saml-setup.md), you can set the **SLO URL** to the IdP's Single Logout endpoint. When a user who authenticated via that IdP signs out of WeftId, WeftId redirects them to the IdP's SLO endpoint so the IdP can terminate its session too.

If the IdP's metadata includes a `SingleLogoutService` element, WeftId imports the SLO URL automatically.

## SLO in WeftId's metadata

WeftId's IdP metadata (available on the SP's **Metadata** tab) advertises the SLO endpoint:

```xml
<md:SingleLogoutService
    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    Location="https://your-domain.com/saml/idp/slo" />
<md:SingleLogoutService
    Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    Location="https://your-domain.com/saml/idp/slo" />
```

Share this metadata with the application so it knows where to send LogoutRequests.

## User signs out of WeftId

When a user clicks **Sign Out**:

1. WeftId clears the user's session immediately.
2. For each application the user accessed during the session that has an SLO URL configured, WeftId builds a signed LogoutRequest containing the user's NameID and session index from the original assertion.
3. Each LogoutRequest is sent via HTTP POST to the application's SLO URL with a 5-second timeout.
4. If the user authenticated via a SAML identity provider that has an SLO URL, WeftId redirects the user to the IdP's SLO endpoint.
5. The user is returned to the sign-in page.

Logout propagation is best-effort. If an application is unreachable or returns an error, the sign-out still completes. The event log records how many applications were notified successfully.

## Application sends a LogoutRequest

When an application initiates logout:

1. The application sends a signed SAML LogoutRequest to WeftId's SLO endpoint (`/saml/idp/slo`) via HTTP-Redirect or HTTP-POST.
2. WeftId validates the request: the issuer must match a registered, enabled service provider with an SLO URL configured.
3. WeftId clears the user's session.
4. WeftId builds a signed LogoutResponse and returns it to the application's SLO URL via HTTP-POST (auto-submitted form).
5. The application receives the LogoutResponse and completes its local logout.

If the LogoutRequest is invalid or comes from an unregistered application, WeftId redirects to the sign-in page without processing the request.

## Signing

All SLO messages (LogoutRequest and LogoutResponse) are signed using RSA-SHA256. WeftId uses the same signing certificate as for SSO assertions: the per-SP signing certificate if one exists, otherwise the tenant-level SAML certificate.

## Audit events

| Event | When |
|-------|------|
| `slo_sp_initiated` | An application sent a LogoutRequest to WeftId |
| `slo_idp_propagated` | WeftId sent LogoutRequests to applications during user sign-out |
