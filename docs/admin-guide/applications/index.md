# Applications

Register the downstream applications and services your users access through WeftID. Applications
covers four kinds of client, each its own tab:

- **SAML** — Downstream applications registered as SAML service providers. WeftID acts as the
  identity provider, issuing SAML assertions so users can access their applications with single
  sign-on. See [Service Providers](../service-providers/index.md).
- **OAuth2 / OIDC** — OAuth2 clients for interactive applications. Users authorize access through
  a consent screen; an app can also enable OIDC to receive a signed identity token. See
  [Apps](../integrations/apps.md) and [Sign in with WeftID (OIDC)](../integrations/oidc-provider-setup.md).
- **Forward Auth** — Gate HTTP applications that have no built-in SSO at your reverse proxy,
  organized as **Domains** (the DNS/web domains you've verified) and **Apps** (the individual
  proxied applications under a verified domain). See [Forward Auth for HTTP Apps](../service-providers/forward-auth.md).
- **Service Accounts** — OAuth2 clients for service-to-service communication using the client
  credentials flow. No user interaction is involved. See [B2B Service Accounts](../integrations/b2b.md).
