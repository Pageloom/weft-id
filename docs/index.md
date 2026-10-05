# WeftID Documentation

WeftID is an identity provider and access management platform. It authenticates users, manages their lifecycle, and provides single sign-on to your applications via SAML 2.0, OpenID Connect, or forward auth at a reverse proxy. Users sign in with a password or passkey, through your organization's identity provider (Okta, Entra ID, Google Workspace, or any SAML or OIDC provider), or with a social account such as Google, GitHub, or Apple.

## For administrators

The [Admin Guide](admin-guide/index.md) covers users and groups, identity providers and social sign-in, applications (SAML, OAuth2 / OIDC, forward auth, service accounts), security settings, and the audit log.

## For end users

The [User Guide](user-guide/index.md) covers signing in, your dashboard and profile, two-step verification, passkeys, and the apps you have authorized.

## For developers

The [API Reference](api/index.md) covers authentication, conventions, and how to access the interactive API documentation.

## Standards conformance

WeftID's OpenID Provider passes the OpenID Foundation conformance suite for the Basic, Config, Form Post, RP-Initiated, Front-Channel, Back-Channel, and 3rd Party-Init OP profiles, and for Dynamic OP apart from one accepted deviation. Signing users in through an upstream OpenID Connect provider, WeftID passes the Basic, Config, RP-Initiated, and Back-Channel RP profiles. See [OpenID Connect Conformance](conformance/oidc.md) for the results, the accepted deviations, and how to rerun the suite.

## Getting started

New to WeftID? Start with the [Getting Started](getting-started/index.md) guide.
