# Identity Providers

WeftID authenticates users directly with its own password and two-step verification system. Optionally, federate with external identity providers (Okta, Entra ID, Google Workspace, or any SAML 2.0 IdP) so users can sign in with their existing credentials instead.

- [SAML Setup](saml-setup.md) — Configure a SAML identity provider connection
- [Inbound SCIM Overview](inbound-scim.md) — Let the upstream IdP push user and group changes into WeftID over SCIM 2.0
- [Inbound SCIM (Okta)](inbound-scim-okta.md) — Step-by-step setup for Okta as the SCIM client
- [Inbound SCIM (Entra)](inbound-scim-entra.md) — Step-by-step setup for Microsoft Entra ID as the SCIM client
- [Privileged Domains](privileged-domains.md) — Domain-based IdP routing and auto-assignment
