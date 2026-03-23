# B2B Service Accounts

B2B clients are OAuth2 clients that use the client credentials flow. They're designed for service-to-service communication where no user interaction is involved. Each B2B client has a dedicated service user that determines what the client can access.

## Creating a B2B client

Navigate to **Admin > Integrations > B2B** and click **Create B2B Client**.

| Field | Required | Description |
|-------|----------|-------------|
| Name | Yes | Display name for the service account (max 255 characters) |
| Description | No | Internal description (max 500 characters) |
| Service Role | Yes | The role assigned to the service user: **Member**, **Admin**, or **Super Admin**. This determines the client's API permissions. |

After creation, WeftID displays the **client ID** and **client secret** in a dialog. Copy and store these credentials securely. The secret is not retrievable after you dismiss the dialog.

WeftID automatically creates a service user linked to the client. This user has the role you specified and acts as the identity for all API requests made with the client's tokens.

## Client credentials flow

B2B clients authenticate directly with their credentials. No user consent is needed.

```
POST /oauth2/token
grant_type=client_credentials&client_id=...&client_secret=...
```

WeftID returns an access token:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

B2B access tokens are valid for 24 hours. No refresh tokens are issued. Request a new token when the current one expires.

## Service roles

The service role determines what the B2B client can do through the API:

| Role | Capabilities |
|------|-------------|
| Member | Read own profile, list accessible applications |
| Admin | Manage users, groups, service providers, identity providers, and settings |
| Super Admin | Full access, including tenant-level operations and user anonymization |

The service role can be changed after creation from the client's detail page.

## Managing a B2B client

Click the client name in the list to open its detail page. From there you can:

- **Edit** the name and description
- **Change the service role** -- Updates the linked service user's role
- **Regenerate the client secret** -- Immediately invalidates the old secret. A new secret is shown once.
- **Deactivate** -- Disables the client and revokes all active tokens. The client can be reactivated later.
- **Reactivate** -- Re-enables a deactivated client.

## Access requirements

Admin or super admin role required to manage B2B clients.
