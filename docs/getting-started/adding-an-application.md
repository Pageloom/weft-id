# Adding an Application

Register a downstream application as a SAML service provider so users can access it with single sign-on.

## Create the service provider

1. Navigate to **Settings > Service Providers**
2. Click **Add Service Provider**
3. Enter a display name (e.g., "Confluence", "Slack")
4. Click **Create**

## Share WeftID's metadata

After creation, WeftID shows an IdP metadata URL specific to this service provider. Copy this URL and configure it in your application's SAML settings.

The metadata includes WeftID's entity ID, SSO endpoint, signing certificate, and supported attributes.

## Import the application's metadata

Once your application is configured, import its SAML metadata into WeftID to complete the connection. Three options are available on the SP's detail page:

- **Metadata URL** -- Paste the application's metadata URL for automatic import
- **Metadata XML** -- Paste the raw SAML metadata XML
- **Manual entry** -- Enter the entity ID and Assertion Consumer Service (ACS) URL directly

After import, the service provider is ready for SSO.

## Configure access

By default, no users can access a new service provider. Assign groups to control which users can sign in:

1. Go to the service provider's **Groups** tab
2. Assign one or more groups
3. Users in those groups can now launch the application from their dashboard

To allow all users access without group restrictions, enable **Available to all** in the SP settings.

## Test the connection

Click the application on your dashboard to launch an IdP-initiated SSO. Verify you are signed in to the application successfully.
