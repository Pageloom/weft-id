# Glossary

Terms and abbreviations used throughout this documentation, organized by topic.

## Federation & Single Sign-On

**Federation**
:   A trust arrangement where separate organizations accept each other's authentication decisions. WeftID acts as a federation broker, sitting between upstream identity providers and downstream applications. Users authenticate once and gain access to multiple services without separate credentials.

**Single Sign-On (SSO)**
:   The ability for a user to authenticate once and access multiple applications without signing in again. WeftID supports SSO via SAML 2.0. There are two initiation patterns: SP-initiated (the user starts at the application) and IdP-initiated (the user starts at WeftID). See [SSO Flow](admin-guide/service-providers/sso-flow.md).

**Single Logout (SLO)**
:   A SAML protocol for propagating sign-out across federated services. When a user signs out of WeftID, logout requests are sent to each application they accessed during the session. SLO is best-effort because downstream applications may not respond. See [Single Logout](admin-guide/service-providers/slo.md).

**Identity Provider (IdP)**
:   A system that authenticates users and issues identity assertions. In WeftID, "upstream IdP" refers to external providers like Okta, Entra ID, or Google Workspace that your users sign in through. WeftID itself also acts as an IdP to downstream applications.

**Service Provider (SP)**
:   An application that relies on an identity provider for authentication. In WeftID, SPs are the downstream applications you register for single sign-on. WeftID issues SAML assertions to SPs so users can access them without separate credentials.

**Trust relationship**
:   A cryptographic agreement between an IdP and an SP, established by exchanging metadata and certificates. Each side knows the other's entity ID and public key, enabling signature verification and secure communication. In WeftID, each connection gets its own trust relationship with independent certificates.

**Consent screen**
:   A confirmation page shown to the user during SSO before WeftID sends an assertion to the application. Displays the application name, the user's identity, and (when group claims are enabled) the groups that will be shared. The user can proceed, cancel, or switch accounts.

## SAML 2.0

**SAML (Security Assertion Markup Language)**
:   An XML-based open standard for exchanging authentication and authorization data between parties. SAML 2.0 is the version used by WeftID. The specification defines message formats (assertions, requests, responses), protocol bindings (how messages are transported), and metadata (how services describe themselves). Published by OASIS. See the [SAML 2.0 specification](http://docs.oasis-open.org/security/saml/v2.0/).

**Assertion**
:   A signed XML document issued by an IdP containing claims about a user (identity, attributes, group memberships). WeftID builds an assertion for each SSO event, signs it with the SP's dedicated signing certificate, and posts it to the application's ACS URL. If the SP provides an encryption certificate, the signed assertion is encrypted before delivery.

**Entity ID**
:   A globally unique identifier for a SAML participant. In WeftID, each connection gets its own entity ID (formatted as a URN), so multiple registrations of the same IdP or SP never collide. Entity IDs are stable and survive infrastructure changes like domain renames.

**SAML metadata**
:   An XML document describing a SAML service's endpoints, certificates, supported attributes, and NameID formats. IdPs and SPs exchange metadata to establish trust. WeftID generates a unique metadata URL for each connection and can import metadata from upstream IdPs and downstream SPs by URL, XML upload, or manual entry.

**ACS URL (Assertion Consumer Service URL)**
:   The endpoint where a service provider receives SAML responses. After authenticating a user, WeftID posts the signed assertion to this URL. Defined in the SP's metadata.

**NameID**
:   The identifier for the user within a SAML assertion. WeftID supports four formats: email address (most common), persistent (stable opaque ID per user per SP), transient (random per session), and unspecified (defaults to email). See [Attribute Mapping](admin-guide/service-providers/attribute-mapping.md).

**AuthnRequest**
:   A SAML message sent by an SP to an IdP requesting user authentication. This is the starting point of SP-initiated SSO. The request identifies which SP is asking and where to send the response.

**LogoutRequest / LogoutResponse**
:   SAML messages used during Single Logout. A LogoutRequest asks the recipient to terminate the user's session. A LogoutResponse confirms (or reports failure of) that termination.

**Binding**
:   The transport mechanism for SAML messages. WeftID supports HTTP-Redirect (message encoded in a URL query parameter) and HTTP-POST (message in a form submission). SLO messages use HTTP-Redirect by default.

**KeyDescriptor**
:   An element in SAML metadata declaring a public key and its intended use (signing or encryption). WeftID reads encryption KeyDescriptors from SP metadata to automatically enable assertion encryption.

## OAuth2 & API Access

**OAuth2**
:   An authorization framework for granting limited access to APIs without sharing credentials. WeftID uses OAuth2 for API integrations, supporting two flows: authorization code (for interactive applications) and client credentials (for service-to-service communication). See [Integrations](admin-guide/integrations/index.md).

**Authorization code flow**
:   An OAuth2 flow for interactive applications. The user authorizes the application in a browser, receives a short-lived authorization code, and the application exchanges that code for access and refresh tokens. Supports PKCE for added security. See [Apps](admin-guide/integrations/apps.md).

**Client credentials flow**
:   An OAuth2 flow for service-to-service communication with no user interaction. The client authenticates directly with its ID and secret to obtain an access token. Used by B2B service accounts. See [B2B Service Accounts](admin-guide/integrations/b2b.md).

**PKCE (Proof Key for Code Exchange)**
:   An OAuth2 extension (pronounced "pixy") that protects the authorization code flow against interception attacks. The client generates a random verifier, sends a hash of it with the authorization request, and proves possession of the original verifier when exchanging the code. Recommended for all interactive applications. Defined in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636).

**Access token**
:   A short-lived credential (bearer token) that authorizes API requests. Issued by WeftID after a successful OAuth2 flow. Include it in the `Authorization` header as `Bearer <token>`.

**Refresh token**
:   A long-lived credential used to obtain new access tokens without re-authorization. Only issued in the authorization code flow. Stored securely by the client application.

## Certificates & Cryptography

**X.509 certificate**
:   A standard format for public key certificates, used in SAML for signing and encryption. Each certificate binds a public key to an identity and has a validity period. WeftID auto-generates per-SP signing certificates.

**Signing certificate**
:   The certificate WeftID uses to digitally sign SAML assertions and logout messages. Each SP connection gets its own signing certificate, so rotating one never affects another. The application uses the certificate's public key (from WeftID's metadata) to verify signatures. See [Signing Certificates](admin-guide/service-providers/sp-certificates.md).

**Encryption certificate**
:   A certificate provided by an SP in its metadata, used by WeftID to encrypt assertions before delivery. Only the SP's private key can decrypt the assertion. Encryption is automatic when the certificate is present. See [Assertion Encryption](admin-guide/service-providers/attribute-mapping.md#assertion-encryption).

**AES-256-CBC**
:   Advanced Encryption Standard with a 256-bit key in Cipher Block Chaining mode. A symmetric encryption algorithm used by WeftID to encrypt the assertion payload. The AES key itself is encrypted with RSA-OAEP so only the SP can recover it.

**RSA-OAEP**
:   RSA encryption with Optimal Asymmetric Encryption Padding. An asymmetric encryption scheme used to wrap the AES content-encryption key during assertion encryption. The SP's encryption certificate provides the RSA public key.

**PEM (Privacy Enhanced Mail)**
:   A text encoding format for certificates and keys, using Base64 between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` markers. WeftID displays signing certificates in PEM format on the Certificates tab.

**Certificate rotation**
:   Replacing a certificate that is approaching expiry with a new one. WeftID supports rotation with a configurable grace period during which both old and new certificates are valid, giving the application time to update its trust configuration. See [Signing Certificates](admin-guide/service-providers/sp-certificates.md#rotation).

**TOTP (Time-Based One-Time Password)**
:   An algorithm that generates short-lived numeric codes from a shared secret and the current time. Used by authenticator apps (Google Authenticator, 1Password, Authy) for two-step verification. Defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

## User & Tenant Management

**Tenant**
:   An isolated organization instance in WeftID. Each tenant has its own users, groups, identity providers, service providers, and settings. Tenants are identified by subdomain (e.g., `acme.id.example.com`) and isolated at the database level.

**Just-in-time provisioning (JIT)**
:   Automatically creating a user account the first time someone signs in through an external identity provider. The user's name, email, and group memberships are populated from the SAML assertion. Eliminates the need to pre-create accounts. See [Creating Users](admin-guide/users/creating-users.md).

**Inactivation**
:   Disabling a user account while preserving all data. Inactivated users cannot sign in but can be reactivated by an admin (or request reactivation themselves). Distinct from anonymization, which is irreversible. See [User Lifecycle](admin-guide/users/user-lifecycle.md).

**Anonymization**
:   Permanently removing a user's personally identifiable information (name, email) while preserving their audit trail. Satisfies GDPR right-to-erasure requirements. Irreversible. See [User Lifecycle](admin-guide/users/user-lifecycle.md).

**Privileged domain**
:   An email domain registered in WeftID with an IdP binding and optional group auto-assignment. Users with matching email addresses are routed to the bound IdP during sign-in and can be automatically added to specified groups. See [Privileged Domains](admin-guide/identity-providers/privileged-domains.md).

## Groups & Access Control

**Group hierarchy**
:   Parent-child relationships between groups, forming a directed acyclic graph (DAG). A group can have multiple parents and multiple children. The only constraint is that no group can be both an ancestor and a descendant of another (no cycles). See [Group Hierarchy](admin-guide/groups/group-hierarchy.md).

**DAG (Directed Acyclic Graph)**
:   A graph structure where edges have direction and no cycles exist. WeftID uses a DAG for group hierarchy rather than a simple tree, allowing groups to have multiple parents. For example, an "Engineering" group could be a child of both "Product" and "Technology".

**Group assertion scope**
:   A setting that controls which group memberships are included in SAML assertions sent to service providers. Three options: "access-granting groups only" (default, shares only groups that grant access to the specific SP), "top-level groups only" (shares the user's highest-level memberships without nested groups), and "all groups" (shares every effective membership). The tenant-wide default is set in security permissions. Each SP can override it. See [Group claims](admin-guide/service-providers/attribute-mapping.md#group-claims).

**Group-based access**
:   Restricting which users can access an application by assigning specific groups to the SP. Only users who belong to an assigned group (directly or through the hierarchy) can access the application. The alternative is "available to all", which grants access to every active user. See [Group-Based Access](admin-guide/groups/group-based-access.md).

**IdP group**
:   A group whose membership is synced from an external identity provider during SAML sign-in. Membership is read-only in WeftID. Created automatically when an IdP sends group assertions.

## Audit & Security

**Event log**
:   A tamper-evident record of every write operation in a tenant: user creation, role changes, SP configuration, sign-in events, and more. Each entry records the actor, timestamp, event type, affected resource, and contextual metadata. See [Audit](admin-guide/audit/index.md).

**Activity tracking**
:   Recording when users last performed read operations (viewing pages, listing resources). Used by the automatic inactivation policy to identify inactive accounts. Distinct from event logging, which records writes.

**Two-step verification**
:   A secondary verification step after password entry. WeftID supports two methods: TOTP via an authenticator app (stronger) and email verification codes (default). Admins can require platform two-step verification for users signing in through an external IdP. See [Two-Step Verification](admin-guide/security/two-step-verification.md).

**Backup codes**
:   Single-use recovery codes generated when setting up TOTP-based two-step verification. Each code can be used once if the authenticator app is unavailable. Store them securely offline.
