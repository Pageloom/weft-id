# OIDC with LinkedIn

Connect LinkedIn as an upstream identity provider so users sign in with their LinkedIn account.

The general mechanics are covered in [OIDC Setup](oidc-setup.md). This page covers what is specific to LinkedIn.

## What the preset supplies

Selecting the **LinkedIn** provider type pre-fills:

* Issuer: `https://www.linkedin.com/oauth`
* Discovery URL: `https://www.linkedin.com/oauth/.well-known/openid-configuration`
* Scopes: `openid profile email`
* Correlation claim: `sub`

LinkedIn's `sub` is unique to your application, and stable for a given member. LinkedIn only accepts the client ID and secret in the body of the token request, not as HTTP Basic credentials. WeftID sends them that way for a LinkedIn connection, so there is nothing to configure.

## Step 1: Create the LinkedIn app

1. Open the [LinkedIn Developer Portal](https://www.linkedin.com/developers/apps) and click **Create app**
2. Fill in the app name and logo, and associate it with a LinkedIn company page (LinkedIn requires one)
3. On the **Products** tab, request **Sign In with LinkedIn using OpenID Connect**. It is granted without review
4. On the **Auth** tab, under **Authorized redirect URLs for your app**, add the callback URL from your WeftID connection's Details tab (you can create the WeftID connection first and fill this in afterwards)
5. Copy the **Client ID** and **Primary Client Secret** from the **Auth** tab

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **LinkedIn**
2. Paste the client ID and client secret
3. Click **Test Connection**, then enable the connection

## Email linking

LinkedIn includes `email_verified` in its tokens, so [email linking](oidc-setup.md#allow-email-linking) can match existing accounts when you turn it on. The security trade-off described there still applies.

## Groups and sign-out

LinkedIn emits no groups claim, so leave the connection's [group claim](oidc-setup.md#group-claims) empty. LinkedIn also publishes no end session endpoint, so **Sign out at the provider** has no effect on this connection.

## Troubleshooting

**`unauthorized_scope_error` on sign-in**
:   The **Sign In with LinkedIn using OpenID Connect** product has not been added to the app. Add it on the **Products** tab.

**"The redirect_uri does not match the registered value"**
:   The URL registered on the **Auth** tab does not exactly match WeftID's. Copy it again from the connection's Details tab.
