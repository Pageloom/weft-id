# Authentication Policy

The tenant authentication policy controls how strong a second factor WeftID requires. It is a super-admin setting on the tenant security page.

## What the policy controls

The policy has one setting, `required_auth_strength`, with two values:

* **Baseline** (default). Email one-time codes count as a valid second factor. Users can sign in with password plus email OTP, password plus TOTP, or a passkey.
* **Enhanced**. Email one-time codes are no longer acceptable. Every user must have either a TOTP authenticator or a passkey registered. Users with only email OTP are redirected to an enrollment page on next sign-in and cannot reach the dashboard until they enroll.

Enhanced is the right choice for any tenant that handles regulated data, serves privileged users, or wants phishing-resistant sign-in for everyone.

## Setting the policy

1. Go to **Settings > Security > Authentication**.
2. Select **Baseline** or **Enhanced**.
3. Save.

The change takes effect immediately. Existing sessions are not interrupted; the policy is evaluated on each new sign-in.

## What happens when you tighten to Enhanced

* Users who already have TOTP or a passkey are unaffected. They continue to sign in as before.
* Users who have only email OTP are redirected to an enrollment page after entering their password and email code. The page offers both **Register a passkey** and **Set up TOTP**. Completing either path satisfies the policy and finishes the sign-in.
* SP-initiated SAML SSO cannot complete while enrollment is pending. The user must finish enrollment before the SSO assertion is issued.

The enrollment block is per-sign-in, not per-user. A user who clears enrollment is simply enrolled; they do not re-enter the flow on subsequent sign-ins unless an admin resets their two-step verification.

## Recovery

If a user is stuck (lost their TOTP device and all backup codes, lost every passkey), an admin can reset their two-step verification from the user detail page:

1. Go to **Users > (user) > Danger**.
2. Click **Reset two-step verification**.

The user's TOTP secret and passkeys are cleared. On their next sign-in they go through the enrollment flow again.

Resetting two-step verification is the recovery path; there is no "one-time baseline exception" that lets a user bypass the enhanced policy.

## Revoking a single passkey

To revoke one passkey without resetting the user entirely:

1. Go to **Users > (user) > Profile**.
2. Scroll to the **Passkeys** section.
3. Click **Revoke** on the passkey you want to remove.

The passkey is deleted immediately and the user must re-register to use it again. The user's other passkeys and TOTP are unchanged. This is the right action for a lost laptop or phone where the user still has a second registered passkey.
