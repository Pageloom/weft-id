# Two-Step Verification

WeftId requires two-step verification for all password-based sign-ins. Users choose between an authenticator app (TOTP) or email-based codes. Email is the default. Users manage their own method from the [two-step verification settings](../../user-guide/two-step-verification.md) page.

## Per-IdP verification requirement

Each identity provider connection has a **Require platform two-step verification** setting. When enabled, users who sign in through that IdP must complete WeftId's verification challenge after SAML authentication, even if the IdP already authenticated them.

This is useful when the IdP does not enforce its own second factor, or when you want a verification step under WeftId's control.

Configure this on the IdP's detail page under connection settings.

## Admin reset

Super admins can reset a user's verification method from the user's detail page. This deletes all TOTP secrets and backup codes. The user reverts to email-based verification on their next sign-in.
