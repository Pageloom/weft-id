# Sign in with Facebook

Connect Facebook so users sign in with their Facebook account.

WeftID uses Facebook Login as plain OAuth 2.0, so a Facebook connection has no issuer, discovery document or ID token for you to configure. WeftID knows Facebook's endpoints and reads the user's profile from the Graph API after they sign in. Everything else (just-in-time provisioning, platform two-step verification, the sign-in page button) works as described in [OIDC Setup](oidc-setup.md). Email linking does not: see below.

## What the preset supplies

Selecting the **Facebook** provider type sets:

* Scopes: `public_profile email`
* Facebook's fixed authorization, token and Graph API endpoints

The issuer, discovery URL and correlation claim fields are hidden for Facebook. Users are matched on their Facebook user ID. Facebook issues a different ID for the same person in each Facebook app, so the users of one connection cannot be matched with those of a connection that uses another app.

The scopes are what each one is for:

* `public_profile`: the user ID, name and profile picture
* `email`: the account's email address

Both have standard access for your own app's login, so they need no App Review.

## Email: confirmed by WeftID, never linked

Facebook reports an email address but does not say whether it has verified it. WeftID therefore treats the address as unproven:

* **Email linking is not available.** A Facebook sign-in is never attached to an existing account because the email addresses match. See [Account linking](account-linking.md)
* **Just-in-time provisioning asks the user to confirm their address.** A new account is created from the Facebook profile, then WeftID emails a code to the address and the sign-in completes only after the user enters it. Until then the address is unverified and the account is not added to the groups linked to the address's domain. A user who abandons the step is asked again on their next Facebook sign-in
* An account without an email address on Facebook (one registered with a phone number) cannot be provisioned

## Step 1: Create a Meta app

Meta reorganizes its developer dashboard often. The names below are as of October 2026.

1. In [Meta for Developers](https://developers.facebook.com/apps), click **Create App**. Name it after your product (users see the name on Facebook's consent screen) and attach it to your business portfolio rather than a personal account
2. Choose the use case **Authenticate and request data from users with Facebook Login**
3. In the use case's **Customize** page, add the **email** permission next to `public_profile`
4. In the use case's **Settings**, paste the callback URL from your WeftID connection's Details tab into **Valid OAuth Redirect URIs** (you can create the WeftID connection first and fill this in afterwards). Leave **Client OAuth login** and **Web OAuth login** on, and **Enforce HTTPS** and **Use Strict Mode for redirect URIs** on
5. In **App settings > Basic**, copy the **App ID** and the **App secret**

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **Facebook**
2. Paste the App ID as the client ID and the App secret as the client secret
3. Save, copy the callback URL from the Details tab into the Meta app if you haven't yet, and click **Test Connection**
4. Enable the connection, and turn on **Show on Sign-In Page** to add a "Continue with Facebook" button (see [Sign-in page buttons](login-buttons.md))

Test Connection asks Facebook for an app access token with the App ID and App secret. It reports whether Facebook rejects them, without anyone signing in. It cannot check the callback URL: Facebook only compares that during a real sign-in.

## Step 3: Go live

A new Meta app is in development mode: only people with a role on the app (administrators, developers, testers) can sign in. Test with one of them, then publish the app so everyone can.

Before Meta lets you publish, fill in **App settings > Basic**:

* **Privacy Policy URL**: a public page describing what your product does with the user's data
* **User data deletion**: either **Data Deletion Instructions URL** (a public page telling users how to have their data deleted, for example by contacting you or deleting their account) or a data deletion callback. WeftID does not provide a callback, so use the instructions URL
* **App icon** and **Category**

Then switch the app from **Development** to **Live** (or **Publish** it, depending on the dashboard version). With only `public_profile` and `email`, publishing needs no App Review. Meta may ask you to complete business verification depending on your account.

## Graph API version

WeftID calls a fixed Graph API version, updated in WeftID releases. Meta retires versions about two years after release, so keep WeftID up to date. The version your app was created with in the Meta dashboard does not need to match.

WeftID signs its Graph calls with `appsecret_proof`, so the app setting **Require App Secret** can be on.

## Groups

Facebook has no groups for WeftID to sync. Leave the group claim on the **Claim Mapping** tab blank.

## Sign-out

Facebook has no sign-out endpoint for this flow and no back-channel logout, so the related settings are hidden. Signing out of WeftID does not sign the user out of Facebook.

## Troubleshooting

**Facebook shows "URL blocked" or "Can't load URL"**
:   The callback URL is not in the app's **Valid OAuth Redirect URIs**, or does not match it exactly. Copy it again from the connection's Details tab.

**Only some people can sign in**
:   The app is still in development mode. See [Go live](#step-3-go-live).

**Test Connection: "Facebook rejected the app ID or app secret"**
:   The App ID or App secret is wrong, or the secret was reset. Copy both again from **App settings > Basic**.

**New users get no account**
:   Their Facebook account has no email address, or they declined to share it on the consent screen. Facebook does not ask again for a permission the user declined. To share it, the user removes your app under **Settings & privacy > Settings > Apps and websites** in Facebook, then signs in again.

**Sign-in fails and the event log shows `facebook_api`**
:   The Graph API call failed after the user authorized the app. Check that the app is not restricted and that the App secret in WeftID is current.
