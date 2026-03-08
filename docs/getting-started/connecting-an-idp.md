# Connecting an Identity Provider

Connect a SAML identity provider (Okta, Entra ID, Google Workspace, or any SAML 2.0 IdP) to allow users to sign in with their existing credentials.

## Create the connection

1. Navigate to **Settings > Identity Providers**
2. Click **Add Identity Provider**
3. Enter a display name (e.g., "Corporate Okta")
4. Select the provider type: Okta, Azure AD, Google Workspace, or Generic SAML
5. Click **Create**

## Share WeftId's metadata with your IdP

After creation, WeftId generates a metadata URL for your new connection. This URL contains the information your IdP needs to trust WeftId as a service provider.

Copy the metadata URL and configure it in your identity provider's admin console. Each provider has a different setup process:

- **Okta** -- Create a new SAML application and paste the metadata URL
- **Entra ID** -- Register an enterprise application with the SAML metadata
- **Google Workspace** -- Configure a custom SAML app with the metadata URL

## Establish trust

Once your IdP is configured, return to WeftId and complete the trust relationship. You can do this in three ways:

- **Metadata URL** -- Paste your IdP's metadata URL. WeftId fetches the certificate, SSO URL, and entity ID automatically.
- **Metadata XML** -- Paste the full SAML metadata XML from your IdP.
- **Manual entry** -- Enter the entity ID and SSO URL, and upload the IdP's signing certificate.

After trust is established, users can sign in through this identity provider.

## Optional: Bind email domains

You can route users to this IdP automatically based on their email domain. See [Privileged Domains](../admin-guide/identity-providers/privileged-domains.md) for details.
