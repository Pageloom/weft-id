# OIDC with Microsoft Entra ID

Connect Microsoft Entra ID (formerly Azure AD) as an upstream identity provider. This is the OIDC route; Entra can also be connected over [SAML](saml-setup.md), and it can additionally push users into WeftID over [SCIM](inbound-scim-entra.md).

The general mechanics are covered in [OIDC Setup](oidc-setup.md). This page covers what is specific to Entra.

## What the preset supplies

Selecting the **Entra** provider type pre-fills:

* Authority, composed from the directory (tenant) ID you enter: `https://login.microsoftonline.com/<tenant-id>/v2.0`
* Scopes: `openid profile email User.Read`
* Correlation claim: `oid`

### Why `oid` and not `sub`

Entra's `sub` claim is pairwise: it is unique to the combination of user and application, so the same person gets a different `sub` in a different app registration. It is stable enough to correlate within one connection, but it carries no meaning outside it and it changes if the app registration is recreated.

The `oid` claim is the user's object ID in the directory and is stable across applications, which is what Microsoft recommends using to identify a user. The preset therefore sets the correlation claim to `oid`.

If you recreate the app registration, an `oid`-correlated connection keeps working. A `sub`-correlated one would orphan every existing link.

## Step 1: Register the application in Entra

1. Open the [Entra admin center](https://entra.microsoft.com/) and go to **Identity > Applications > App registrations**
2. Click **New registration** and give it a name
3. Under **Redirect URI**, select **Web** and paste the redirect URI from your WeftID connection's Details tab
4. Click **Register**
5. Copy the **Application (client) ID** and the **Directory (tenant) ID** from the overview page
6. Go to **Certificates & secrets > New client secret**, create one, and copy its **value** immediately (it is shown only once)

Note that Entra shows both a secret **value** and a secret **ID**. WeftID needs the value.

## Step 2: Configure the WeftID connection

1. In WeftID, go to **Settings > OIDC Identity Providers** and create a connection with provider type **Entra**
2. Enter the **directory (tenant) ID** — WeftID composes the authority URL from it
3. Paste the client ID and the client secret value
4. Click **Test connection**, then enable it

The tenant ID field also accepts `organizations` (any work or school account) or `common` (work, school, or personal Microsoft accounts). Use your specific directory ID unless you deliberately want a multi-tenant application, since the broader values allow sign-ins from directories you do not control.

## Client secret expiry

Entra client secrets expire, up to a maximum of 24 months. When the secret expires, sign-ins through the connection stop working. Note the expiry date when you create the secret and rotate it before then: create a new secret in Entra, paste it into the WeftID connection, and remove the old one from Entra.

## Groups

The Entra `groups` claim emits directory object IDs (GUIDs) rather than group names, and resolving them requires additional Microsoft Graph permissions. Group synchronisation over OIDC is not supported by this connection. To bring Entra groups into WeftID, use [inbound SCIM](inbound-scim-entra.md).

## Troubleshooting

**`AADSTS50011: redirect URI mismatch`**
:   The URI registered on the app registration does not exactly match WeftID's. Copy it again from the connection's Details tab.

**`AADSTS7000215: invalid client secret`**
:   The secret has expired, or the secret **ID** was pasted instead of the secret **value**. Create a new secret and paste its value.

**`AADSTS650057: invalid resource`**
:   The requested scopes are not consented. Check that `User.Read` is granted on the app registration's API permissions.

**Users appear with no first or last name**
:   The `profile` scope is not being released, or the directory has no `givenName`/`surname` for those accounts. Check the connection's claim mapping and the directory records.
