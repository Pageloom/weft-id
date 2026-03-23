# Integrations

Create OAuth2 clients so external applications and services can authenticate with the WeftID API. Navigate to **Admin > Integrations**.

WeftID supports two client types:

- [Apps](apps.md) — OAuth2 clients for interactive applications. Users authorize access through a consent screen, and the application receives tokens on their behalf (authorization code flow).
- [B2B Service Accounts](b2b.md) — OAuth2 clients for service-to-service communication. No user interaction required. The service authenticates directly with its credentials and acts as a dedicated service user (client credentials flow).

## Common operations

Both client types support:

- **Deactivation** -- Soft-disables the client and revokes all active tokens. The client can be reactivated later.
- **Secret regeneration** -- Issues a new client secret and immediately invalidates the old one.
- **Deletion** -- Permanently removes the client and all associated tokens and authorization codes.

## Client secrets

Client secrets are shown **once** at creation time. Store the secret securely before dismissing the credentials dialog. If you lose the secret, regenerate it from the client's detail page.

Secrets are stored as cryptographic hashes. WeftID cannot retrieve the original secret after creation.
