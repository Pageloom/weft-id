# Attribute Mapping

Attribute mapping controls which user attributes WeftId includes in the SAML assertion sent to a service provider.

## Default attributes

Every assertion includes these attributes:

| Attribute | Value |
|-----------|-------|
| `email` | User's primary email address |
| `firstName` | User's first name |
| `lastName` | User's last name |
| `displayName` | First and last name combined |

## Group claims

To include the user's group memberships in the assertion, enable **Include group claims** on the SP's settings. When enabled, a `groups` attribute is added containing the names of all groups the user belongs to.

## Custom mappings

If the application expects attributes with specific names, configure custom mappings on the SP's **Attributes** tab. Each mapping translates a WeftId attribute to the name the application expects.

For example, if the application expects `urn:oid:0.9.2342.19200300.100.1.3` for email, create a mapping from `email` to that OID.

## Auto-detection

When you import an SP's metadata, WeftId reads the application's requested attributes and suggests mappings automatically. You can review and adjust these on the **Attributes** tab.

## NameID format

The NameID identifies the user in the assertion. Configure the format on the SP's settings:

| Format | Value | Use case |
|--------|-------|----------|
| **Email** | User's primary email | Most common. Simple and human-readable. |
| **Persistent** | Stable opaque ID per user per SP | When the user's email might change. |
| **Transient** | Random value per session | When no persistent identifier is needed. |
| **Unspecified** | User's email (default) | When the SP does not specify a preference. |
