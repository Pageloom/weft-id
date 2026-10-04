# Sign-In Page Buttons

Put a **Continue with ...** button on the sign-in page for any OIDC connection. Users click it and go straight to the provider, without typing an email address first. This is how social sign-in works for consumer providers such as Google or LinkedIn, whose email domains (gmail.com and so on) cannot be bound to a connection.

Nothing appears on the sign-in page until a super admin turns it on for a connection.

## Add a button

1. Go to **Identity Providers > OIDC** and open the connection.
2. On the **Details** tab, under **Settings**, check **Show on Sign-In Page**. Make sure **Enabled** is checked too.
3. Click **Save Settings**.

You can also check **Show on Sign-In Page** when you create the connection. The button appears once the connection is enabled. A disabled connection never shows a button, and its details tab warns you when the setting is on but the connection is off.

Through the API, set `show_on_login` to `true` on `POST /api/v1/oidc-upstream/connections` or `PATCH /api/v1/oidc-upstream/connections/{connection_id}`.

## What users see

The buttons sit above the email field, one per connection, in alphabetical order of connection name. The email field stays, so users who sign in with a password, a passkey, or SAML are not affected.

Each button carries the provider's name and logo:

* **Google**: "Continue with Google"
* **Microsoft Entra ID** and **Microsoft personal accounts**: "Continue with Microsoft"
* **LinkedIn**: "Continue with LinkedIn"
* **GitLab**: "Continue with GitLab"
* **GitHub**: "Continue with GitHub"
* **Discord**: "Continue with Discord"
* **Facebook**: "Continue with Facebook"
* **Apple**: "Continue with Apple" (white with a black outline in light mode, black in dark mode, as Apple's guidelines require)
* **Generic OIDC**: "Continue with" followed by the connection name, with no logo. Name the connection the way users know the provider.

Buttons appear on the first step of sign-in only, not on the password step.

## What happens after the click

The button starts the same flow as email sign-in, and the provider sends the user back to the same callback. WeftID then matches the provider account to a WeftID account exactly as described in [Account linking](account-linking.md):

* An account already linked to that provider account signs in.
* With **Allow email linking** on, a verified email address can link the provider account to an existing WeftID account.
* With **JIT provisioning** on, a new account is created. For a provider that does not verify email addresses (Facebook, Microsoft personal accounts), the user first confirms their address with a code WeftID emails them.
* Otherwise the sign-in is refused and the user is told no account was found.

So decide who may get in before adding a button. For open sign-up, turn on JIT provisioning. To let only existing users in, leave JIT off. Users assigned to a SAML identity provider are always refused and told to sign in with their email address.

A button does not skip **Require two-step verification**, if the connection has it on.

## Email verification for new users

Whether a new user meets an extra step depends on the provider. The connection's **Show on Sign-In Page** setting tells you which applies.

* **No extra step**: Google, Microsoft Entra ID, LinkedIn, GitLab, GitHub, Discord and Apple only share email addresses they have verified, so a new account's address counts as verified straight away.
* **Code by email**: Facebook and Microsoft personal accounts do not prove that the user controls the address. A new user must enter a code WeftID sends to it before their first sign-in completes. Until they do, every sign-in through that provider asks for the code again.
* **Generic OIDC**: no extra step. Whether the address was verified depends on the identity provider.

Apple users may hide their address behind an Apple private relay address. WeftID treats it as verified. To deliver email to it (invitations, sign-in codes), register your sending domain with Apple. See [Apple](oidc-apple.md#private-relay-email-addresses).

## Event log

Sign-ins through a connection record the same events whether they start from a button or from email routing: **OIDC upstream login initiated**, **User signed in via OIDC upstream** (or **User created via OIDC just-in-time provisioning** for a first sign-in that creates the account), **OIDC upstream login attempt failed**, and **OIDC upstream sign-in refused by the account-linking policy**. Each carries an `entry` value in its details:

* `login_button`: the user clicked the connection's button on the sign-in page.
* `routed`: the user got there any other way, such as email routing or the default connection.

Turning the button on or off is recorded as **OIDC upstream identity provider connection updated**, with `show_on_login` among the updated fields.
