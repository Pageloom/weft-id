# SAML Setup

Connect a SAML 2.0 identity provider to WeftID. This enables users to sign in with their existing credentials from Okta, Entra ID, Google Workspace, or any SAML-compliant IdP.

## Step 1: Create the connection

1. Navigate to **Settings > Identity Providers**
2. Click **Add Identity Provider**
3. Enter a display name
4. Select the provider type (Okta, Azure AD, Google Workspace, or Generic SAML)
5. Click **Create**

Selecting a provider type pre-fills attribute mappings for known providers.

## Step 2: Configure your IdP

After creation, WeftID generates a metadata URL for this connection. The metadata contains:

- WeftID's entity ID (unique per IdP connection)
- Assertion Consumer Service (ACS) URL
- WeftID's SP signing certificate

Share this metadata URL with your IdP. In your IdP's admin console, create a new SAML application using WeftID's metadata.

Each IdP connection gets its own entity ID and certificate. This means you can connect the same upstream IdP multiple times (for example, two Okta orgs during a company merger) and manage each connection independently.

## Step 3: Establish trust

Return to WeftID and complete the trust relationship using one of three methods:

| Method | When to use |
|--------|-------------|
| **Metadata URL** | Your IdP publishes a metadata URL. WeftID fetches everything automatically. |
| **Metadata XML** | You have the IdP's metadata as an XML file or string. |
| **Manual entry** | Enter the entity ID, SSO URL, and upload the certificate individually. |

Once trust is established, the connection is active and users can sign in through this IdP.

## Connection settings

After trust is established, you can configure additional settings on the IdP detail page:

| Setting | Description |
|---------|-------------|
| **Enabled** | Toggle the IdP on or off without deleting it. |
| **Require platform two-step verification** | Force users to complete WeftID two-step verification after SAML sign-in. |
| **JIT provisioning** | Automatically create user accounts on first SAML sign-in. |
| **SLO URL** | Single Logout URL for sending logout requests to the IdP. |

## Attribute mapping

WeftID maps SAML assertion attributes to user fields. Default mappings are pre-filled based on the provider type:

| WeftID field | Typical attribute |
|-------------|-------------------|
| Email | `emailaddress` claim or NameID |
| First name | `givenname` claim |
| Last name | `surname` claim |
| Groups | `groups` claim |

You can customize these mappings on the IdP's **Attributes** tab.

## Metadata refresh

If your IdP has a metadata URL configured, you can refresh it to pick up certificate rotations or configuration changes. Click **Refresh Metadata** on the IdP detail page.

## Deleting an IdP

An IdP cannot be deleted while it has email domain bindings. Remove all domain bindings first, then delete. Any IdP-synced groups will be marked as invalid but preserved for audit purposes.
