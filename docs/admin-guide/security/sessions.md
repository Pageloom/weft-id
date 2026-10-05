# Sessions

Configure how long user sessions last, how WeftID handles inactive accounts, and the sign-in verification mode.

Navigate to **Security > Sessions**.

## Maximum session length

How long a user can remain signed in before they must re-authenticate.

* Indefinitely (default, no time limit)
* 8 hours
* One to six days
* One week
* Two weeks

Changes apply immediately. Users whose sessions exceed the new limit are signed out on their next request.

Signing out ends a session on the server as well as in the browser, so a copy of the session cookie stops working
too. Sessions also end when a connected OIDC identity provider reports that the user signed out there (see
[OIDC Setup](../identity-providers/oidc-setup.md#sign-out-from-the-provider)).

## Persistent sessions

When enabled, sessions survive browser (and computer) restarts. When disabled, users must sign in again each time they
open their browser.

Default is enabled.

## Automatic deactivation

Automatically deactivate users who haven't been active for a set period. Once deactivated, an admin must reactivate them
before they can sign in again.

* Disabled (default, users are never deactivated)
* 14 days
* 30 days
* 60 days
* 90 days

If every super admin ends up deactivated, a self-hosted instance can recover from the server. See
[Recovering a locked-out super admin](../../self-hosting/index.md#recovering-a-locked-out-super-admin).

## Sign-in verification

Controls whether users must verify email possession before being routed to their sign-in method.

**Disabled (default).** Users enter their email and are routed immediately to their password form or identity provider. Unknown emails and deactivated accounts see the password form with no status disclosure. This is the faster experience and matches how most identity platforms work. IP-based rate limiting prevents bulk enumeration.

**Enabled.** Users must enter a one-time email code before WeftID reveals their sign-in method. This prevents any information disclosure about whether an account exists or what authentication method it uses. Enable this for deployments where enumeration resistance is a priority.

The forgot-password flow serves as the proof-of-possession discovery mechanism regardless of this setting. See [Signing In](../../user-guide/signing-in.md) for the end-user perspective.
