# OIDC with Microsoft Personal Accounts

Connect personal Microsoft accounts (Outlook.com, Hotmail, Xbox, Skype) as an upstream identity provider. For work or school accounts in your organization's directory, use [Microsoft Entra ID](oidc-entra.md) instead.

The general mechanics are covered in [OIDC Setup](oidc-setup.md). This page covers what is specific to personal Microsoft accounts.

## What the preset supplies

Selecting the **Microsoft (personal accounts)** provider type pre-fills:

* Issuer: `https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0`
* Discovery URL: `https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration`
* Scopes: `openid profile email`
* Correlation claim: `sub`

The issuer is not the `consumers` address you sign in through. Microsoft issues every personal-account token from the fixed directory that holds all personal accounts, and WeftID checks tokens against that issuer.

### Why `sub` and not `oid`

The Entra preset correlates on `oid`, but personal-account tokens do not carry one. Their `sub` is stable for a given user and application registration, so it is the correlation claim here. If you replace the app registration, its `sub` values change and existing users are treated as new subjects.

## Step 1: Register the application

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com/)
2. Go to **Identity > Applications > App registrations** and click **New registration**
3. Under **Supported account types**, choose **Personal Microsoft accounts only**
4. Under **Redirect URI**, choose **Web** and paste the redirect URI from your WeftID connection's Details tab
5. Click **Register** and copy the **Application (client) ID**
6. Go to **Certificates & secrets > Client secrets**, create a secret, and copy its **Value** (not its ID)

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **Microsoft (personal accounts)**
2. Paste the client ID and client secret
3. Click **Test connection**, then enable it

## Client secret expiry

Client secrets expire (the portal defaults to six months). When a secret expires, sign-in through the connection fails at the token exchange. Create a new secret before the old one expires and paste it into the connection.

## Email linking

Personal-account tokens do not include `email_verified`, and the account's email address need not be one the user controls. WeftID therefore never [links by email](account-linking.md#which-providers-can-link-by-email) on this connection, and the **Allow email linking** setting is unavailable for it. New users are provisioned (with JIT on) or refused. A provisioned user confirms their email address with a code WeftID emails them before their first sign-in completes (see [Confirming an unverified email address](account-linking.md#confirming-an-unverified-email-address)).

## Groups

Personal accounts have no groups, so leave the connection's [group claim](oidc-setup.md#group-claims) empty. Users still land in the connection's base group.

## Troubleshooting

**"The client does not exist or is not enabled for consumers"**
:   The app registration does not accept personal accounts. Change **Supported account types** to include personal Microsoft accounts.

**AADSTS50011: the redirect URI does not match**
:   The redirect URI registered in Entra does not exactly match WeftID's. Copy it again from the connection's Details tab.

**AADSTS7000215: invalid client secret**
:   The secret's ID was pasted instead of its value, or the secret has expired.
