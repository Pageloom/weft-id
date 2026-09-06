# Identity Providers

WeftID authenticates users directly with its own password and two-step verification system. Optionally, federate with external identity providers (Okta, Entra ID, Google Workspace, Keycloak, Auth0, or any SAML 2.0 or OpenID Connect provider) so users can sign in with their existing credentials instead.

SAML and OIDC are peers. A tenant can run connections of both kinds at the same time, and each connection is managed independently.

- [SAML Setup](saml-setup.md) — Configure a SAML identity provider connection
- [OIDC Setup](oidc-setup.md) — Configure an OpenID Connect connection for any spec-compliant provider
- [OIDC with Google Workspace](oidc-google.md) — Step-by-step setup for Google as an OIDC provider
- [OIDC with Microsoft Entra ID](oidc-entra.md) — Step-by-step setup for Entra as an OIDC provider
- [Inbound SCIM Overview](inbound-scim.md) — Let the upstream IdP push user and group changes into WeftID over SCIM 2.0
- [Inbound SCIM (Okta)](inbound-scim-okta.md) — Step-by-step setup for Okta as the SCIM client
- [Inbound SCIM (Entra)](inbound-scim-entra.md) — Step-by-step setup for Microsoft Entra ID as the SCIM client
- [Privileged Domains](privileged-domains.md) — Domain-based IdP routing and auto-assignment
