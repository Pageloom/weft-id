# SAML Setup

Connect a SAML 2.0 identity provider to WeftID. This enables users to sign in with their existing credentials from Okta, Entra ID, Google Workspace, or any SAML-compliant IdP.

## Step 1: Create the connection

1. Navigate to **Identity Providers > SAML**
2. Click **Add SAML Provider**
3. Enter a display name
4. Select the provider type (Okta, Azure AD, Google Workspace, or Generic SAML)
5. Click **Create SAML Provider**

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

## Single Logout

When the IdP has an SLO URL, signing out of WeftID also signs the user out at the IdP. WeftID sends the IdP a signed logout request, and the IdP returns the browser to WeftID's SLO endpoint (`https://<your-tenant>.example.com/saml/slo`, listed in WeftID's SP metadata). This also happens when an app signs the user out through WeftID's OpenID Connect end session endpoint. The browser then finishes at the app's post-logout redirect URI.

Signing out at the IdP ends the WeftID session too, when the IdP sends its logout request through the browser. WeftID accepts the request only if it is signed with one of the IdP's certificates and addressed to WeftID's SLO endpoint. It ends the session only if the session came from that IdP with the same name ID (and session index, when the request gives one). WeftID then answers the IdP with a signed logout response. The ended session is audited as `user_signed_out` with reason `upstream_saml_slo`. A request that fails the checks ends nothing and is audited as `saml_idp_logout_rejected`.

Logout requests the IdP sends server to server (SOAP, or a POST without the user's browser) are answered but end no WeftID session. WeftID only knows which session to end from the browser's cookie.

## Attribute mapping

WeftID maps SAML assertion attributes to user fields. Default mappings are pre-filled based on the provider type:

| WeftID field | Typical attribute |
|-------------|-------------------|
| Email | `emailaddress` claim or NameID |
| First name | `givenname` claim |
| Last name | `surname` claim |
| Groups | `groups` claim |

You can customize these mappings on the IdP's **Attributes** tab.

### Standard profile attributes

If your tenant has any [standard profile attributes](../security/user-attributes.md)
enabled with **Mirror from IdP** turned on, each one appears on the **Attributes** tab
as an additional mapping row. Enter the SAML attribute name the IdP uses for that
field. On the next sign-in:

* If the IdP includes the attribute in the assertion, the value is copied into the
  user's profile (and into the per-IdP audit record on the user detail page).
* If **Mirror from IdP** is off for that attribute (tenant setting), the value is
  recorded in the audit record but is not copied into the profile.
* If the assertion omits the attribute, the existing profile value is preserved.

Use the per-user **Connected IdP attributes** section on the user detail page to
verify what each IdP is sending.

### Attribute resilience

WeftID handles missing or incomplete attributes gracefully:

* **Email** is the only required attribute. If the assertion omits the email attribute, WeftID falls back to the NameID value (when it looks like an email address).
* **First name** and **last name** are optional. If missing from the assertion, WeftID preserves the user's existing values.

This prevents sign-in failures when an IdP omits optional fields.

### User attribute sync

When a SAML user signs in, WeftID compares their first and last name from the assertion against the stored values. If they differ (and the assertion provides non-empty values), the stored values are updated automatically. This keeps user profiles in sync with the upstream IdP without manual intervention.

Attribute syncs are recorded as `user_attributes_synced` events in the [audit log](../audit/index.md).

## Metadata refresh

If your IdP has a metadata URL configured, you can refresh it to pick up certificate rotations or configuration changes. Click **Refresh Metadata** on the IdP detail page.

## SAML debug log

When authentication failures occur, WeftID logs detailed diagnostics. Super admins can view these at **Audit > SAML Debug Log**. Each entry includes the error type, the raw SAML response XML, parsed attributes, and request metadata (IP address, user agent). Use this to troubleshoot signature errors, certificate mismatches, and attribute mapping issues.

To enable logging for successful assertions (for temporary debugging), toggle **Verbose logging** on the IdP detail page.

## Deleting an IdP

Delete an IdP from its **Disable/Delete** tab. Deletion is blocked until:

* The IdP is disabled
* No users are assigned to it (move them to another IdP or to password sign-in)
* No email domains are bound to it

IdP-synced groups are marked invalid but kept for audit purposes.

### Clearing mirrored attributes

The delete dialog has a **Clear user profile values mirrored from this IdP** checkbox, checked by default. WeftID clears canonical profile values that still match the IdP's last-mirrored snapshot. Values the user or an admin has since changed are kept. Uncheck it to keep all mirrored values, for example a display name or job title the user still needs.

Cleared keys per user are recorded in `user_profile_updated` events. The `saml_idp_deleted` event records `scrubbed: true` and the user count.

The API does the same by default. To keep mirrored values, call `DELETE /api/v1/saml/idps/{id}?scrub_mirrored_attributes=false`.
