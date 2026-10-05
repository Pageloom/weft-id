# Service Accounts

Service accounts are OAuth2 clients that use the client credentials flow. They're for service-to-service communication where no user is involved. Each service account has a dedicated service user, whose role determines what the account can do through the API.

## Creating a service account

Navigate to **Applications > Service Accounts** and click **Create Service Account**.

| Field | Required | Description |
|-------|----------|-------------|
| Name | Yes | Display name for the service account (max 255 characters) |
| Description | No | Internal description (max 500 characters) |
| Service Role | Yes | The role assigned to the service user: **Member**, **Admin**, or **Super Admin**. This determines the account's API permissions. |

After creation, WeftID displays the **client ID** and **client secret** in a dialog. Copy and store these credentials securely. The secret is not retrievable after you dismiss the dialog.

WeftID automatically creates a service user linked to the account. This user has the role you specified and acts as the identity for all API requests made with the account's tokens.

## Client credentials flow

A service account authenticates directly with its credentials. No user consent is needed.

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

Service account access tokens are valid for 24 hours. No refresh tokens are issued. Request a new token when the current one expires.

## Service roles

The service role determines what the service account can do through the API:

| Role | Capabilities |
|------|-------------|
| Member | Read own profile, list accessible applications |
| Admin | Manage users, groups, service providers, identity providers, and settings |
| Super Admin | Full access, including tenant-level operations and user anonymization |

You can change the service role later on the account's detail page.

## Managing a service account

Click the account name in the list to open its detail page. From there you can:

- **Edit** the name and description.
- **Change the service role**. This updates the linked service user's role.
- **Change client authentication**. Have the account sign a JWT with its own private key instead of sending a secret. See [Private Key JWT](private-key-jwt.md).
- **Allow token introspection for all tenant tokens**. Lets the account check any token in the tenant, for a service that acts as a resource server (an API backend that receives tokens issued to your apps). See [Token Introspection and Revocation](token-introspection.md).
- **Regenerate the client secret**. The old secret stops working immediately. The new one is shown once. Not available while the account uses private key JWT.
- **Deactivate**. The account can no longer request tokens, and its existing tokens are revoked. You can reactivate it later.
- **Reactivate**. Re-enables a deactivated account.

## Access requirements

Super admin role required to manage service accounts.
