# Passwords

Configure password strength requirements, manage forced resets, and monitor for breached credentials.

Navigate to **Settings > Security > Passwords** (super admin only).

## Minimum password length

The shortest password users can set. Options: 8, 10, 12, 14 (recommended), 16, 18, or 20 characters.

Super admins always require at least 14 characters, regardless of this setting.

## Minimum strength score

Passwords are scored by pattern analysis that detects dictionary words, keyboard patterns, repetition, and dates. Two levels are available:

* **Strong (score 3)** -- Default. Rejects passwords with obvious patterns.
* **Very strong (score 4)** -- Requires more complex passwords.

Users see a real-time strength meter as they type, showing the score, estimated crack time, and suggestions for improvement.

## Breach detection

Passwords are checked against the [Have I Been Pwned](https://haveibeenpwned.com/) database at the time they are set. Only the first 5 characters of the password hash are transmitted (k-anonymity), so the actual password is never exposed. Passwords found in known breaches are rejected.

WeftId also runs a weekly background check against the same database. If a user's password appears in a newly disclosed breach:

1. The user is flagged for a forced password reset.
2. Their OAuth2 tokens are revoked.
3. All admins receive an email notification.

The user must choose a new password on their next sign-in.

## Forced password reset

Admins can require any password-authenticated user to change their password on next sign-in. From a user's detail page, open the **Danger** tab and click **Force Password Reset**.

When the user next signs in:

1. They authenticate with their current password as usual.
2. Instead of reaching the dashboard, they see a "Password Reset Required" page.
3. They must choose a new password that meets the current strength requirements.
4. After resetting, they proceed to two-step verification and then the dashboard.

Forced resets revoke the user's OAuth2 tokens immediately. The user's browser session is also terminated on their next page request, forcing them to sign in again and complete the reset.

!!! note
    Forced reset is also triggered automatically when the weekly breach detection finds a compromised password. See [Breach detection](#breach-detection) above.

## Password change

Users can change their own password at any time from **Account > Password**. They must enter their current password and choose a new one. The new password cannot be the same as the current password.

See the [User Guide > Password](../../user-guide/password.md) for the user-facing documentation.

## Audit events

All password operations are logged in the [event log](../audit/index.md):

* `password_changed` -- User changed their own password
* `password_reset_forced` -- Admin forced a password reset
* `password_reset_completed` -- User completed a forced reset
* `password_reset_requested` -- User requested a self-service reset link
* `password_self_reset_completed` -- User completed a self-service reset
* `password_breach_detected` -- Weekly check found a compromised password
