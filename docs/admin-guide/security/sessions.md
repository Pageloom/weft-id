# Sessions

Configure how long user sessions last, how WeftID handles inactive accounts, and the sign-in verification mode.

Navigate to **Settings > Security > Sessions**.

## Maximum session length

How long a user can remain signed in before they must re-authenticate.

* Indefinitely
* One to six days
* One week
* Two weeks (default)

## Persistent sessions

When enabled, sessions survive browser (and computer) restarts. When disabled, users must sign in again each time they
open their browser.

Default is enabled.

## Automatic inactivation

Automatically inactivate users who haven't been active for a set period. Once inactivated, an admin must reactivate them
before they can sign in again. The default is 90 days.

* Disabled (users are never inactivated)
* 14 days
* 30 days
* 60 days
* 90 days (default)

## Sign-in verification

Controls whether users must verify email possession before being routed to their sign-in method.

**Disabled (default).** Users enter their email and are routed immediately to their password form or identity provider. Unknown emails and inactivated accounts see the password form with no status disclosure. This is the faster experience and matches how most identity platforms work. IP-based rate limiting prevents bulk enumeration.

**Enabled.** Users must enter a one-time email code before WeftID reveals their sign-in method. This prevents any information disclosure about whether an account exists or what authentication method it uses. Enable this for deployments where enumeration resistance is a priority.

The forgot-password flow serves as the proof-of-possession discovery mechanism regardless of this setting. See [Signing In](../../user-guide/signing-in.md) for the end-user perspective.
