# OIDC with Google Workspace

Connect Google Workspace as an upstream identity provider so users sign in with their Google account. This is the OIDC route; Google can also be connected over [SAML](saml-setup.md).

The general mechanics are covered in [OIDC Setup](oidc-setup.md). This page covers what is specific to Google.

## What the preset supplies

Selecting the **Google** provider type pre-fills:

* Issuer and discovery URL: `https://accounts.google.com`
* Scopes: `openid profile email`
* Correlation claim: `sub`

Google's `sub` is stable per user and does not change when someone's email address changes, so no correlation quirk is needed.

## Step 1: Create the OAuth client in Google Cloud

1. Open the [Google Cloud console](https://console.cloud.google.com/) and select or create a project
2. Go to **APIs & Services > OAuth consent screen**, choose **Internal** for a Workspace-only application, and complete the required fields
3. Go to **APIs & Services > Credentials** and click **Create Credentials > OAuth client ID**
4. Choose **Web application** as the type
5. Under **Authorized redirect URIs**, add the redirect URI from your WeftID connection's Details tab
6. Click **Create** and copy the client ID and client secret

Choosing **Internal** on the consent screen restricts sign-in to your Workspace organization and avoids Google's verification review. An **External** client will show an unverified-app warning until it is reviewed.

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **Google**
2. Paste the client ID and client secret
3. Optionally set a **hosted domain** (see below)
4. Click **Test connection**, then enable it

## Hosted domain restriction

The **hosted domain** setting adds Google's `hd` parameter to the authorization request. Google then only offers accounts from that Workspace domain and rejects personal Gmail accounts.

Set it to your Workspace domain, for example `example.com`.

This is a useful guard, but it is enforced by Google at the point of sign-in rather than by WeftID on the returned token. If you need WeftID itself to constrain which users may enter, combine it with a [privileged domain](privileged-domains.md) binding and leave JIT provisioning off for accounts you do not want created automatically.

## Groups

Google does not emit a groups claim over OIDC. Group membership is not synchronised by this connection; manage groups in WeftID, or use a directory sync.

## Troubleshooting

**`redirect_uri_mismatch`**
:   The URI registered in Google Cloud does not exactly match WeftID's. Copy it again from the connection's Details tab, including the scheme and any trailing path.

**Users from outside the Workspace can sign in**
:   The hosted domain is not set, or the OAuth client is configured as External. Set the hosted domain on the connection.

**"Access blocked: this app's request is invalid"**
:   Usually a missing redirect URI or an incomplete consent screen. Check both in the Google Cloud console.
