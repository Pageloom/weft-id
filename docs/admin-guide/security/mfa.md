# Multi-Factor Authentication

WeftId supports TOTP (authenticator app) and email-based MFA. Users manage their own MFA enrollment from the [MFA settings](../../user-guide/mfa.md) page.

## Per-IdP MFA requirement

Each identity provider connection has a **Require platform MFA** setting. When enabled, users who sign in through that IdP must complete WeftId's MFA challenge after SAML authentication, even if the IdP already authenticated them.

This is useful when the IdP does not enforce MFA itself, or when you want a second factor under WeftId's control.

Configure this on the IdP's detail page under connection settings.

## Admin MFA reset

Super admins can reset a user's MFA from the user's detail page. This deletes all MFA data (TOTP secrets and backup codes). The user must set up MFA again on their next sign-in if required.
