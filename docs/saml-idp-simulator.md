# SAML IdP Simulator

A local SimpleSAMLphp Identity Provider for testing SAML authentication flows during development.

## Quick Start

The SAML IdP simulator is included in the docker-compose setup and starts automatically:

```bash
docker compose up -d
```

The IdP is available at:
- **HTTP:** http://localhost:8080/simplesaml
- **HTTPS:** https://localhost:8443/simplesaml

## Test Users

The following test users are pre-configured:

| Email | Password | Role |
|-------|----------|------|
| `admin@example.com` | `password123` | Admin user |
| `user@example.com` | `password123` | Regular user |
| `alice@acme.com` | `password123` | User (different domain) |
| `newuser@example.com` | `password123` | For JIT provisioning tests |

## Configuring the App to Use the Simulator

### Step 1: Get the IdP Metadata URL

The IdP metadata is available at:

```
http://localhost:8080/simplesaml/saml2/idp/metadata.php
```

Or via HTTPS:

```
https://localhost:8443/simplesaml/saml2/idp/metadata.php
```

### Step 2: Add the IdP in the App

1. Log in as a super admin
2. Navigate to **Admin > Identity Providers**
3. Click **Add Identity Provider**
4. Fill in the form:
   - **Name:** `Local Dev IdP`
   - **Provider Type:** `Generic SAML 2.0`
   - **Metadata URL:** `http://saml-idp:8080/simplesaml/saml2/idp/metadata.php`

   Or manually configure:
   - **Entity ID:** `http://localhost:8080/simplesaml/saml2/idp/metadata.php`
   - **SSO URL:** `http://localhost:8080/simplesaml/saml2/idp/SSOService.php`
   - **Certificate:** Copy from the IdP metadata page

5. Configure attribute mapping (see below)
6. Click **Create Identity Provider**
7. Enable the IdP

### Step 3: Configure Attribute Mapping

The simulator sends attributes in standard SAML claim format. Configure these mappings in the IdP settings:

| App Field | SAML Attribute |
|-----------|----------------|
| Email | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| First Name | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname` |
| Last Name | `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname` |

Or use the short names if your app supports them:
- `email`
- `firstName`
- `lastName`

## Network Configuration

### From the App Container

When the app container needs to reach the IdP (for metadata fetching), use the Docker network hostname:

```
http://saml-idp:8080/simplesaml/saml2/idp/metadata.php
```

### From Your Browser

When your browser redirects to the IdP for authentication, use localhost:

```
http://localhost:8080/simplesaml/saml2/idp/SSOService.php
```

### ACS URL (Automatic)

The app uses a single Assertion Consumer Service (ACS) URL for all SAML IdPs:

```
https://dev.pageloom.localhost/saml/acs
```

This is the industry-standard approach. The app determines which IdP sent the response by extracting the `Issuer` from the SAML assertion. No per-IdP URL configuration is needed—SP metadata "just works."

## Testing the Flow

1. **Verify the IdP is running:**
   ```bash
   curl http://localhost:8080/simplesaml/
   ```

2. **Access the IdP admin interface:**
   - URL: http://localhost:8080/simplesaml/admin
   - Username: `admin`
   - Password: `secret`

3. **Test a SAML login:**
   - Log out of the app
   - Click "Sign in with SSO"
   - Select your configured IdP
   - Enter test user credentials at the IdP login page
   - Verify you're redirected back and logged in

## Troubleshooting

### "Invalid signature" errors

This usually means the IdP certificate in your app configuration doesn't match the actual IdP certificate. Re-import the metadata or manually copy the certificate from the IdP metadata page.

### "Assertion Consumer Service URL mismatch"

The ACS URL in the SAML request doesn't match what the IdP expects. Ensure the IdP has your SP metadata with the correct ACS URL (`/saml/acs`). The simulator's `saml20-sp-remote.php` is pre-configured with the correct URL.

### Cannot reach IdP from app container

Use the Docker network hostname (`saml-idp`) instead of `localhost` when the app needs to fetch metadata.

### Browser cannot reach IdP

Use `localhost:8080` or `localhost:8443` when your browser needs to access the IdP directly.

### Clock skew errors

SAML assertions have time-based validity. Ensure your system clock is accurate and consider adjusting the `NotBefore` tolerance if needed.

## Advanced: Customizing Test Users

To add or modify test users, edit `simplesamlphp/authsources.php`:

```php
'newuser@company.com:mypassword' => [
    'uid' => ['newuser'],
    'email' => ['newuser@company.com'],
    'firstName' => ['New'],
    'lastName' => ['User'],
    'displayName' => ['New User'],
    'groups' => ['users'],
],
```

After editing, restart the container:

```bash
docker compose restart saml-idp
```

## SimpleSAMLphp Admin Interface

Access the full SimpleSAMLphp admin interface at:

- URL: http://localhost:8080/simplesaml/admin
- Username: `admin`
- Password: `secret`

From here you can:
- View IdP metadata
- Test authentication sources
- Debug SAML messages
- View federation metadata

## Certificates

The IdP certificates are auto-generated on first startup. They're stored in a Docker volume (`saml-idp-certs`) and persist across restarts.

To regenerate certificates, remove the volume:

```bash
docker compose down
docker volume rm loom_saml-idp-certs
docker compose up -d
```

## Files

| File | Purpose |
|------|---------|
| `simplesamlphp/authsources.php` | Test user credentials |
| `simplesamlphp/saml20-idp-hosted.php` | IdP configuration |
| `simplesamlphp/saml20-sp-remote.php` | SP metadata registered with IdP |
| `simplesamlphp/docker-entrypoint.sh` | Auto-generates IdP certificates |

## See Also

- [Manual Testing: SAML Phase 1](manual-testing-saml.md) - Comprehensive test cases
- [SimpleSAMLphp Documentation](https://simplesamlphp.org/docs/stable/)
