# WeftID Documentation

WeftID is an identity provider and access management platform. It authenticates users, manages their lifecycle, and provides single sign-on to your applications via SAML 2.0, OpenID Connect, or forward auth for a reverse proxy. Organizations that already use Okta, Entra ID, Google Workspace, or other identity management systems can be federated into WeftID over SAML or OIDC for seamless, unified sign-in.

## For administrators

The [Admin Guide](admin-guide/index.md) covers user management, group hierarchies, identity provider configuration, service provider registration, security settings, and audit logging.

## For end users

The [User Guide](user-guide/index.md) covers your dashboard, profile settings, and two-step verification.

## For developers

The [API Reference](api/index.md) covers authentication, conventions, and how to access the interactive API documentation.

## Standards conformance

WeftID's OpenID Provider passes the OpenID Foundation conformance suite for the Basic, Config, Form Post, RP-Initiated, Front-Channel, Back-Channel, and 3rd Party-Init OP profiles, and for Dynamic OP apart from one accepted deviation. Signing users in through an upstream OpenID Connect provider, WeftID passes the Basic, Config, RP-Initiated, and Back-Channel RP profiles. See [OpenID Connect Conformance](conformance/oidc.md) for the results, the accepted deviations, and how to rerun the suite.

## Getting started

New to WeftID? Start with the [Getting Started](getting-started/index.md) guide.
