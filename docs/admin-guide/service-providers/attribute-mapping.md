# Attribute Mapping

Attribute mapping controls which user attributes WeftID includes in the SAML assertion sent to a service provider.

## Default attributes

Every assertion includes these attributes:

| Attribute | Value |
|-----------|-------|
| `email` | User's primary email address |
| `firstName` | User's first name |
| `lastName` | User's last name |
| `displayName` | First and last name combined |

## Group claims

To include the user's group memberships in the assertion, enable **Share group membership information** on the SP's **Attributes** tab. When enabled, a `groups` attribute is added to the assertion.

### Group assertion scope

Which groups are included depends on the **group assertion scope** setting. The tenant-wide default is set in **Settings > Security > [Permissions](../security/permissions.md)**. Each SP can override it on its **Attributes** tab.

| Scope | What's shared |
|-------|--------------|
| **Access-granting groups only** (default) | Only the groups that grant the user access to this SP (via [group assignments](../groups/group-based-access.md)). For SPs set to "available to all", top-level groups are shared instead since there are no access-granting groups. |
| **Top-level groups only** | The user's highest-level group memberships. Nested groups are omitted. A top-level group is one where none of the user's other effective groups is an ancestor of it. |
| **All groups** | Every group the user belongs to, including nested and inherited groups. |

**Scope resolution order:**

1. If **Share group membership information** is disabled on the SP, no groups are shared (regardless of scope).
2. If the SP has a scope override, that scope is used.
3. Otherwise, the tenant default applies.

The [consent screen](sso-flow.md#consent-screen) shows users exactly which groups will be shared before they approve the sign-in.

## Custom mappings

If the application expects attributes with specific names, configure custom mappings on the SP's **Attributes** tab. Each mapping translates a WeftID attribute to the name the application expects.

For example, if the application expects `urn:oid:0.9.2342.19200300.100.1.3` for email, create a mapping from `email` to that OID.

## Auto-detection

When you import an SP's metadata, WeftID reads the application's requested attributes and suggests mappings automatically. You can review and adjust these on the **Attributes** tab.

## NameID format

The NameID identifies the user in the assertion. Configure the format on the SP's settings:

| Format | Value | Use case |
|--------|-------|----------|
| **Email** | User's primary email | Most common. Simple and human-readable. |
| **Persistent** | Stable opaque ID per user per SP | When the user's email might change. |
| **Transient** | Random value per session | When no persistent identifier is needed. |
| **Unspecified** | User's email (default) | When the SP does not specify a preference. |

## Assertion encryption

If the application provides an encryption certificate in its SAML metadata, WeftID encrypts the signed assertion using RSA-OAEP key transport. Only the application's private key can decrypt it.

The **Attributes** tab shows the current encryption status:

- **Encrypted** -- The application's metadata includes an encryption certificate. Assertions are encrypted before delivery.
- **Unencrypted** -- No encryption certificate was found in the metadata. Assertions are sent in plain signed XML.

### Encryption algorithm

When encryption is active, a dropdown on the **Attributes** tab lets you choose the content encryption algorithm:

- **AES-256-CBC** (default) -- Compatible with all SAML implementations.
- **AES-256-GCM** -- Requires XML Encryption 1.1 support. Provides authenticated encryption (integrity and confidentiality in a single pass). Verify your application supports it before enabling.

If the application's metadata advertises supported encryption methods, WeftID shows them below the dropdown. When metadata declares only GCM, WeftID auto-selects GCM on import.

### Enabling encryption

To enable encryption for an application that doesn't currently advertise a certificate, update the application's SAML metadata to include an encryption `KeyDescriptor`, then re-import the metadata in WeftID.
