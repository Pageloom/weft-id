# SSO Flow

WeftID supports two single sign-on flows: SP-initiated (started by the application) and IdP-initiated (started from WeftID).

## SP-initiated SSO

This is the most common flow. The user starts at the application and is redirected to WeftID to authenticate.

1. **User visits the application.** The application generates a SAML AuthnRequest and redirects the user to WeftID's SSO endpoint.
2. **WeftID authenticates the user.** If the user is not already signed in, they are prompted to sign in (passkey, password, or SAML IdP).
3. **Two-step verification.** If the user signs in with a password, they must complete two-step verification. If the IdP requires platform two-step verification, IdP users must also complete that step. Passkey sign-in skips this step (passkeys are inherently multi-factor).
4. **Consent.** WeftID shows a consent screen displaying the application name and the user's identity. The user confirms or cancels.
5. **Access check.** WeftID verifies the user has access to the SP (via group assignment or "available to all").
6. **Assertion issued.** WeftID builds a signed SAML response containing the user's attributes. If the application provides an [encryption certificate](attribute-mapping.md#assertion-encryption), the assertion is encrypted before delivery. The response is posted to the application's ACS URL.
7. **User is signed in** to the application.

## IdP-initiated SSO

The user starts from WeftID and launches an application from their dashboard.

1. **User clicks an application** on the WeftID dashboard.
2. **Access check.** WeftID verifies the user has access.
3. **Consent.** The consent screen is shown.
4. **Assertion issued.** WeftID builds and posts the SAML response to the application.
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

## Replay prevention

Each SAML assertion is cached by its unique ID after processing. If the same assertion is submitted a second time (within its validity window, up to 10 minutes), WeftID rejects it. This prevents replay attacks where an intercepted assertion is resubmitted to gain unauthorized access.

## What's in the assertion

The SAML assertion contains:

- **Issuer** -- WeftID's entity ID (unique per SP connection)
- **NameID** -- User identifier in the configured format (email, persistent, or transient)
- **Attributes** -- Email, first name, last name, display name, and optionally group memberships (filtered by the effective [group assertion scope](attribute-mapping.md#group-assertion-scope))
- **Session index** -- Unique session identifier for [Single Logout](slo.md) correlation
- **Signature** -- Signed with the SP's per-SP signing certificate
- **Encryption** -- If the application provides an encryption certificate, the signed assertion is encrypted (AES-256-CBC or AES-256-GCM, RSA-OAEP key transport). See [Assertion Encryption](attribute-mapping.md#assertion-encryption).
