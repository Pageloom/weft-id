# Apps

Apps are OAuth2 clients that use the authorization code flow. They're designed for web applications, mobile apps, and other interactive applications where a user authorizes access through a consent screen.

## Creating an app

Navigate to **Admin > Integrations > Apps** and click **Create App**.

| Field | Required | Description |
|-------|----------|-------------|
| Name | Yes | Display name shown to users on the consent screen (max 255 characters) |
| Description | No | Internal description (max 500 characters) |
| Redirect URIs | Yes | One URI per line. Exact match required, no wildcards. These are the URLs the user is redirected to after authorization. |

After creation, WeftId displays the **client ID** and **client secret** in a dialog. Copy and store these credentials securely. The secret is not retrievable after you dismiss the dialog.

## Authorization code flow

1. Your application redirects the user to WeftId's authorization endpoint:

    ```
    GET /oauth2/authorize?client_id=...&redirect_uri=...&state=...
    ```

2. The user sees a consent screen showing your application's name and their identity. They click **Allow** or **Deny**.

3. If allowed, WeftId redirects to your `redirect_uri` with an authorization code:

    ```
    https://your-app.com/callback?code=...&state=...
    ```

4. Your application exchanges the code for tokens at the token endpoint:

    ```
    POST /oauth2/token
    grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&client_secret=...
    ```

5. WeftId returns an access token and refresh token:

    ```json
    {
      "access_token": "...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": "..."
    }
    ```

### PKCE support

WeftId supports Proof Key for Code Exchange (PKCE) for public clients that cannot securely store a client secret. Include `code_challenge` and `code_challenge_method` in the authorization request, and `code_verifier` in the token exchange. Supported methods: `S256` (recommended) and `plain`.

### Token lifetimes

| Token | Lifetime |
|-------|----------|
| Authorization code | 10 minutes |
| Access token | 1 hour |
| Refresh token | 90 days |

Use the refresh token to obtain new access tokens without requiring the user to re-authorize:

```
POST /oauth2/token
grant_type=refresh_token&refresh_token=...&client_id=...&client_secret=...
```

## Managing an app

Click the app name in the list to open its detail page. From there you can:

- **Edit** the name, description, and redirect URIs
- **Regenerate the client secret** -- Immediately invalidates the old secret. A new secret is shown once.
- **Deactivate** -- Disables the client and revokes all active tokens. The app can be reactivated later.
- **Reactivate** -- Re-enables a deactivated app. Users will need to re-authorize.

## Access requirements

Admin or super admin role required to manage apps.
