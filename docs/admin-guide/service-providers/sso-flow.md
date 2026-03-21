# SSO Flow

WeftId supports two single sign-on flows: SP-initiated (started by the application) and IdP-initiated (started from WeftId).

## SP-initiated SSO

This is the most common flow. The user starts at the application and is redirected to WeftId to authenticate.

1. **User visits the application.** The application generates a SAML AuthnRequest and redirects the user to WeftId's SSO endpoint.
2. **WeftId authenticates the user.** If the user is not already signed in, they are prompted to sign in (password, SAML IdP, or both).
3. **Two-step verification.** If the IdP requires platform two-step verification, the user must complete that step.
4. **Consent.** WeftId shows a consent screen displaying the application name and the user's identity. The user confirms or cancels.
5. **Access check.** WeftId verifies the user has access to the SP (via group assignment or "available to all").
6. **Assertion issued.** WeftId builds a signed SAML response containing the user's attributes. If the application provides an [encryption certificate](attribute-mapping.md#assertion-encryption), the assertion is encrypted before delivery. The response is posted to the application's ACS URL.
7. **User is signed in** to the application.

## IdP-initiated SSO

The user starts from WeftId and launches an application from their dashboard.

1. **User clicks an application** on the WeftId dashboard.
2. **Access check.** WeftId verifies the user has access.
3. **Consent.** The consent screen is shown.
4. **Assertion issued.** WeftId builds and posts the SAML response to the application.
5. **User is signed in** to the application.

## Consent screen

The consent screen shows:

- The application name
- The user's name and email
- The groups that will be shared (if [group claims](attribute-mapping.md#group-claims) are enabled for the SP). If the list exceeds ten groups, a "Show all" toggle reveals the rest.
- A **Continue** button to proceed
- A **Cancel** button to return to the dashboard
- A **Switch account** option to sign in as a different user

The groups displayed on the consent screen are the same groups that will appear in the assertion, filtered according to the effective [group assertion scope](attribute-mapping.md#group-assertion-scope).

## What's in the assertion

The SAML assertion contains:

- **Issuer** -- WeftId's entity ID (unique per SP connection)
- **NameID** -- User identifier in the configured format (email, persistent, or transient)
- **Attributes** -- Email, first name, last name, display name, and optionally group memberships (filtered by the effective [group assertion scope](attribute-mapping.md#group-assertion-scope))
- **Session index** -- Unique session identifier for [Single Logout](slo.md) correlation
- **Signature** -- Signed with the SP's per-SP signing certificate
- **Encryption** -- If the application provides an encryption certificate, the signed assertion is encrypted (AES-256-CBC, RSA-OAEP key transport). See [Assertion Encryption](attribute-mapping.md#assertion-encryption).
