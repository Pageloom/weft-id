# Two-Step Verification

WeftID requires two-step verification for all password-based sign-ins. Users choose between an authenticator app (TOTP), email-based codes, or [passkeys](../../user-guide/passkeys.md). Email is the default. Users manage their own method from the [two-step verification settings](../../user-guide/two-step-verification.md) page.

To require stronger methods tenant-wide (disallowing email codes), see [Authentication Policy](authentication-policy.md).

## Per-IdP verification requirement

Each identity provider connection has a **Require platform two-step verification** setting. When enabled, users who sign in through that IdP must complete WeftID's verification challenge after SAML authentication, even if the IdP already authenticated them.

This is useful when the IdP does not enforce its own second factor, or when you want a verification step under WeftID's control.

Configure this on the IdP's detail page under connection settings.

## Admin reset

Super admins can reset a user's verification method from the user's detail page. This deletes the user's TOTP secret and backup codes. Registered passkeys are not affected. The user reverts to email-based verification on their next sign-in.

To revoke individual passkeys, go to **Users > (user) > Profile > Passkeys** and click **Revoke** on the specific credential.
