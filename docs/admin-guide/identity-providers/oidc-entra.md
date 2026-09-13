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

1. In WeftID, go to **Identity Providers > OIDC** and create a connection with provider type **Entra**
2. Enter the **directory (tenant) ID** — WeftID composes the authority URL from it
3. Paste the client ID and the client secret value
4. Click **Test connection**, then enable it

The tenant ID field also accepts `organizations` (any work or school account) or `common` (work, school, or personal Microsoft accounts). Use your specific directory ID unless you deliberately want a multi-tenant application, since the broader values allow sign-ins from directories you do not control.

## Client secret expiry

Entra client secrets expire, up to a maximum of 24 months. When the secret expires, sign-ins through the connection stop working. Note the expiry date when you create the secret and rotate it before then: create a new secret in Entra, paste it into the WeftID connection, and remove the old one from Entra.

## Groups

Entra can put the user's groups in the ID token, and WeftID can sync them into IdP groups (see [group claims](oidc-setup.md#group-claims)). Two things to know before enabling it.

**The claim carries object IDs, not names.** Entra's `groups` claim emits directory object IDs (GUIDs). WeftID uses them verbatim, so the synced groups are named by GUID under the connection's base group. That works for group-based access (assign the GUID-named group to an application), but the names are not friendly. Resolving GUIDs to display names needs `GroupMember.Read.All` or `Directory.Read.All` and Microsoft Graph calls. WeftID does not do that today; whether it should is a separate decision from this feature, not something the connection needs. If you want friendly names, use [inbound SCIM](inbound-scim-entra.md), which pushes groups by display name.

**Overage.** When a user is in more groups than fit in the token (200 for a JWT), Entra omits the `groups` claim and sends a `_claim_names` pointer to Microsoft Graph instead. WeftID detects this, records an `oidc_group_claim_overage` event against the connection, and leaves that user's memberships unchanged rather than emptying them.

To enable the claim:

1. On the app registration, open **Token configuration > Add groups claim**
2. Choose which groups to emit and keep the **Group ID** format for the ID token. Restricting it to groups assigned to the application keeps tokens small and avoids overage
3. In WeftID, open the connection's **Claim mapping** tab and set the group claim name to `groups`

## Troubleshooting

**`AADSTS50011: redirect URI mismatch`**
:   The URI registered on the app registration does not exactly match WeftID's. Copy it again from the connection's Details tab.

**`AADSTS7000215: invalid client secret`**
:   The secret has expired, or the secret **ID** was pasted instead of the secret **value**. Create a new secret and paste its value.

**`AADSTS650057: invalid resource`**
:   The requested scopes are not consented. Check that `User.Read` is granted on the app registration's API permissions.

**Users appear with no first or last name**
:   The `profile` scope is not being released, or the directory has no `givenName`/`surname` for those accounts. Check the connection's claim mapping and the directory records.
