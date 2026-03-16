# Registering a Service Provider

Register a downstream application as a SAML service provider to enable single sign-on.

## Step 1: Create the service provider

1. Navigate to **Settings > Service Providers**
2. Click **Add Service Provider**
3. Enter a display name
4. Click **Create**

## Step 2: Share WeftId's metadata

After creation, WeftId generates a metadata URL specific to this SP. The metadata contains:

- WeftId's entity ID (unique per SP connection)
- SSO endpoint URL
- Signing certificate
- Supported attributes and NameID formats

Copy this URL and configure it in your application's SAML settings.

Each SP gets its own entity ID and signing certificate, so connections are fully independent. You can register the same application multiple times (for example, staging and production environments) without conflicts, and rotating a certificate for one SP never affects another.

## Step 3: Import the application's metadata

Once your application is configured, return to the SP's detail page and import its metadata:

| Method | When to use |
|--------|-------------|
| **Metadata URL** | The application publishes a metadata URL. WeftId fetches and parses it automatically. |
| **Metadata XML** | You have the application's SAML metadata as XML. |
| **Manual entry** | Enter the entity ID and ACS URL directly. |

WeftId auto-detects the application's requested attributes and NameID format from its metadata.

## Step 4: Configure access

New service providers have no users assigned. Choose an access mode:

- **Group-based access** -- Assign specific groups on the SP's **Groups** tab. Only users in those groups can access the application.
- **Available to all** -- Enable this setting to allow all active users to access the application.

The SP list shows a **Users** column so you can see how many users can access each application. SPs set to "Available to all" show a blue badge. Group-based SPs show the count of unique active users across all assigned groups (including users in descendant groups).

## Logo

Upload a custom logo from the SP's detail page to help users identify the application on their dashboard and in consent screens.

- **Formats:** PNG or SVG
- **PNG requirements:** Square, at least 48x48 pixels, maximum 256 KB
- **SVG requirements:** Square viewBox (or none), maximum 256 KB. Scripts and event handlers are stripped for security.

The logo appears in the SP list, detail page, user dashboard, and SSO consent screen. If no logo is uploaded, an auto-generated acronym avatar is shown instead.

To remove a logo, click **Remove Logo** on the SP's detail page.

## Service provider settings

| Setting | Description |
|---------|-------------|
| **Enabled** | Toggle the SP on or off without deleting it. |
| **NameID format** | How users are identified in assertions: email, persistent, transient, or unspecified. |
| **Include group claims** | Include the user's group memberships in the SAML assertion. |

## Deleting a service provider

Remove all group assignments before deleting an SP.
