# Sign in with Discord

Connect Discord so users sign in with their Discord account.

Discord is not an OpenID Connect provider. It uses plain OAuth 2.0, so a Discord connection has no issuer, discovery document or ID token for you to configure. WeftID knows Discord's endpoints and reads the user's profile from the Discord API after they sign in. Everything else (just-in-time provisioning, email linking, platform two-step verification, the sign-in page button) works as described in [OIDC Setup](oidc-setup.md).

## What the preset supplies

Selecting the **Discord** provider type sets:

* Scopes: `identify email`
* Discord's fixed authorization, token and API endpoints

The issuer, discovery URL and correlation claim fields are hidden for Discord. Users are matched on their Discord user ID, which stays the same when they change their username or email address.

The scopes are what each one is for:

* `identify`: the account (user ID, username, display name, avatar)
* `email`: the account's email address and whether Discord has verified it

## Step 1: Create a Discord application

1. In the [Discord Developer Portal](https://discord.com/developers/applications), click **New Application**, name it, and accept the terms. Users see this name on Discord's consent screen. Create it under a Discord team rather than a personal account, so it survives the person who created it leaving
2. Open the application's **OAuth2** page
3. Under **Redirects**, click **Add Redirect** and paste the callback URL from your WeftID connection's Details tab (you can create the WeftID connection first and fill this in afterwards)
4. Leave **Public Client** off. WeftID keeps the client secret on the server
5. Copy the **Client ID**, then click **Reset Secret** and copy the client secret

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **Discord**
2. Paste the client ID and client secret
3. Save, copy the callback URL from the Details tab into the Discord application if you haven't yet, and click **Test Connection**
4. Enable the connection, and turn on **Show on Sign-In Page** to add a "Continue with Discord" button (see [Sign-in page buttons](login-buttons.md))

Test Connection sends the client ID and client secret to Discord. It reports whether Discord rejects them, without anyone signing in. It cannot check the callback URL: Discord only compares that during a real sign-in.

## Email and names

WeftID only uses the account's email address when Discord has verified it. An account with an unverified address signs in without an email, so it cannot be provisioned or [email-linked](account-linking.md) until the user verifies the address in Discord. A user who already has a linked account still signs in.

Discord has a single display name. WeftID takes the first word as the first name and the rest as the last name. A user with no display name gets their Discord username as their first name.

## Groups

Discord has no groups for WeftID to sync. Server (guild) membership is not requested, so leave the group claim on the **Claim Mapping** tab blank.

## Sign-out

Discord has no sign-out endpoint and no back-channel logout, so the related settings are hidden. Signing out of WeftID does not sign the user out of Discord.

## Troubleshooting

**Discord shows "Invalid OAuth2 redirect_uri"**
:   The callback URL in the Discord application's **Redirects** does not exactly match WeftID's. Copy it again from the connection's Details tab.

**Test Connection: "Discord rejected the client ID or client secret"**
:   The client ID or secret is wrong, or the secret was reset in the Developer Portal. Reset it again and set the new one on the connection through the API (see [Changing credentials later](oidc-setup.md#changing-credentials-later)).

**New users are not created**
:   Their Discord email address is unverified, so WeftID has no address to create the account with. The event log shows a failed sign-in. The user verifies their email in Discord's settings and signs in again.

**Sign-in fails and the event log shows `discord_api`**
:   The Discord API call failed after the user authorized the application. A missing `identify` scope is the usual cause: check the connection's scopes.
