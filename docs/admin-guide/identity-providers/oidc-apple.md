# Sign in with Apple

Connect Apple so users sign in with their Apple Account.

Sign in with Apple is OpenID Connect, so WeftID uses Apple's discovery document and verifies the ID tokens Apple signs. It differs from other providers in a few ways, all covered on this page:

* There is no client secret to copy. You give WeftID a private key, and WeftID signs a short-lived client secret with it for every sign-in
* Apple sends the user's name only once, on their first sign-in
* Users can hide their email address behind an Apple private relay address

You need a paid membership of the Apple Developer Program.

## What the preset supplies

Selecting the **Apple** provider type sets:

* Issuer: `https://appleid.apple.com`, and Apple's discovery URL
* Scopes: `openid name email`
* Correlation claim: `sub`

Users are matched on the `sub` Apple issues. It is stable for one person and one team: every Services ID in the same Apple Developer team gets the same `sub` for a user.

## Step 1: Set up Sign in with Apple at Apple

Apple reorganizes its developer site from time to time. The names below are as of October 2026. All four steps are in [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/identifiers/list).

1. **App ID.** Under **Identifiers**, create an App ID (or pick an existing one) and enable the **Sign in with Apple** capability. This is the primary App ID your Services ID belongs to
2. **Services ID.** Under **Identifiers**, create a **Services ID**. Its description is what users see on Apple's consent screen; its identifier (for example `com.example.signin`) is the client ID WeftID needs. Enable **Sign in with Apple** on it and click **Configure**:
    * **Primary App ID**: the App ID from step 1
    * **Domains and Subdomains**: your WeftID tenant host, for example `acme.weftid.example.com`
    * **Return URLs**: the callback URL from your WeftID connection's Details tab (you can create the WeftID connection first and fill this in afterwards). Apple accepts only `https` URLs on a real domain
3. **Key.** Under **Keys**, create a key with **Sign in with Apple** enabled, configured for the primary App ID. Download the `.p8` file (Apple lets you download it only once) and note the **Key ID**
4. **Team ID.** Your team ID is shown in the top right of the developer site, and under **Membership details**

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **Apple**
2. Enter the Services ID identifier as the **Client ID**
3. Enter the **Team ID** and **Key ID**, and paste the whole `.p8` file into **Private Key**, including the `BEGIN` and `END` lines. WeftID encrypts the key and never shows it again
4. Save, copy the callback URL from the Details tab into the Services ID's **Return URLs** if you haven't yet, and click **Test Connection**
5. Enable the connection, and turn on **Show on Sign-In Page** to add a "Continue with Apple" button (see [Sign-in page buttons](login-buttons.md))

Test Connection fetches Apple's discovery document and signing keys, then signs a client secret with your key and presents it to Apple's token endpoint. It reports whether Apple rejects the Services ID, team ID, key ID or key, without anyone signing in. It cannot check the return URL: Apple only compares that during a real sign-in.

To replace the key (for example after revoking it at Apple), edit the **Apple Signing Key** card on the Details tab. Fields you leave blank keep their current value.

## Names

Apple shares the user's name only on their first sign-in to your Services ID. WeftID uses it for an account created by just-in-time provisioning. On later sign-ins there is no name to read.

If the first sign-in did not create an account (for example, JIT provisioning was off), the name is not sent again. The user can reset this by removing your app under **Sign in with Apple** in their Apple Account settings and signing in again. Otherwise an admin can edit the user's name in WeftID.

## Email addresses

Apple only shares email addresses it has verified, so a new account's address counts as verified straight away and **Allow Email Linking** is available. See [Account linking](account-linking.md).

### Private relay email addresses

When signing in, a user can choose **Hide My Email**. Apple then gives WeftID an address such as `x7k2m9q4pz@privaterelay.appleid.com` that forwards to the user's real inbox. WeftID treats it like any other verified address:

* A relay address never matches an existing account's address, so email linking cannot attach the sign-in to an existing account. With JIT provisioning on, a new account is created
* Apple forwards email to a relay address only from senders you have registered. Without this, invitations, sign-in codes and other WeftID email to these users never arrives

To register WeftID's sending domain, go to **Certificates, Identifiers & Profiles > Services > Sign in with Apple for Email Communication**, add the domain WeftID sends from (your `SMTP_FROM` domain) or the exact address, and make sure the domain passes SPF and DKIM.

## Groups

Apple has no groups for WeftID to sync. Leave the group claim on the **Claim Mapping** tab blank.

## Sign-out

Apple has no sign-out endpoint and no back-channel logout. Signing out of WeftID does not sign the user out of their Apple Account.

## Troubleshooting

**Apple shows "invalid_request" or "Invalid web redirect url"**
:   The callback URL is not in the Services ID's **Return URLs**, or does not match it exactly. Copy it again from the connection's Details tab.

**Apple shows "invalid_client"**
:   The client ID is not a Services ID with Sign in with Apple enabled. Use the Services ID identifier, not the App ID.

**Test Connection: "Apple rejected the client secret"**
:   The team ID, key ID or key is wrong, the key was revoked, or the key is not configured for the Services ID's primary App ID. Check all three, or create a new key and paste it.

**New users have no name**
:   See [Names](#names).

**Users with a relay address get no email**
:   WeftID's sending domain is not registered with Apple. See [Private relay email addresses](#private-relay-email-addresses).

**Sign-in fails and the event log shows `state_mismatch`**
:   The sign-in took longer than ten minutes, was started in another browser, or was replayed. The user can start again.
