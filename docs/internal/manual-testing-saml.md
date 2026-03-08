# Manual Testing: SAML Phase 1

This document provides test cases for manually testing SAML SSO functionality.

## Prerequisites

- Application running locally (typically `http://localhost:8000`)
- Super admin account to configure IdP
- A test Identity Provider (see options below)

## Test IdP Options

### Option 1: samling (Local Docker)

A simple SAML IdP simulator:

```bash
docker run -p 8080:8080 capriza/samling
```

Access `http://localhost:8080` to configure responses.

### Option 2: samltest.id (Online)

Free online test IdP at https://samltest.id

### Option 3: Real IdP Dev Account

- **Okta Developer** - Free at https://developer.okta.com
- **Azure AD** - Free tier available
- **Google Workspace** - If you have admin access

---

## Test Case 1: End-to-End SAML Login

### Objective

Verify complete SAML authentication flow from IdP configuration to user login.

### Steps

#### 1. Access Identity Providers Page

1. Log in as super admin
2. Navigate to **Admin > Identity Providers** (`/admin/identity-providers`)
3. **Verify:** Page loads without errors
4. **Verify:** "Add Identity Provider" button is visible
5. **Verify:** SP Metadata section shows metadata URL (if SP cert exists)

#### 2. Create an IdP Configuration

1. Click "Add Identity Provider"
2. **Verify:** Form loads at `/admin/identity-providers/new`
3. Fill in the form:
   - **Name:** `Test IdP`
   - **Provider Type:** `Generic SAML 2.0`
   - **Entity ID:** (from your test IdP, e.g., `http://localhost:8080/samling/idp`)
   - **SSO URL:** (from your test IdP, e.g., `http://localhost:8080/samling/idp/sso`)
   - **Certificate:** Paste the IdP's public certificate in PEM format
   - **Attribute Mapping:** Use defaults or adjust for your IdP
   - Leave "Enabled" unchecked initially
4. Click "Create Identity Provider"
5. **Verify:** Redirected to list page with success message
6. **Verify:** New IdP appears in the list with "Disabled" status

#### 3. Configure Test IdP with SP Metadata

1. On the IdP list page, locate the SP Metadata section
2. Copy the metadata URL or click "View XML" to see the SP metadata
3. Note these key values:
   - **SP Entity ID:** `http://localhost:8000/saml/metadata`
   - **ACS URL:** `http://localhost:8000/saml/acs/{idp_id}`
4. Configure your test IdP with these values
5. **For samling:** Paste the SP metadata URL or configure manually

#### 4. Enable the IdP

1. Click "Enable" next to the IdP in the list
2. **Verify:** Status changes to "Enabled"
3. **Verify:** Success message displayed

#### 5. Set as Default (Optional)

1. Click "Set Default" next to the IdP
2. **Verify:** "Default" badge appears next to the IdP name

#### 6. Test Login Flow

1. Log out of the application
2. Go to the login page (`/login`)
3. **Verify:** "Sign in with SSO" option is visible
4. Click "Sign in with SSO"
5. **If single IdP:** Should redirect directly to IdP
6. **If multiple IdPs:** Should show IdP selection page (`/saml/select`)
7. Authenticate at the test IdP
8. **Verify:** Redirected back to application
9. **Verify:** Session created and logged in

#### 7. Verify Event Logging

1. As an admin, go to **Admin > Event Log**
2. **Verify:** `user_signed_in_saml` event is logged
3. **Verify:** Event metadata includes IdP details

---

## Test Case 2: IdP Management Operations

### Edit IdP

1. Navigate to `/admin/identity-providers`
2. Click "Edit" on an existing IdP
3. Modify the name or other settings
4. Save changes
5. **Verify:** Changes are persisted

### Toggle Enable/Disable

1. Click "Disable" on an enabled IdP
2. **Verify:** Status changes to "Disabled"
3. **Verify:** SSO login with this IdP is blocked
4. Click "Enable" to re-enable
5. **Verify:** SSO login works again

### Delete IdP

1. Click "Delete" on an IdP
2. **Verify:** Confirmation dialog appears
3. Confirm deletion
4. **Verify:** IdP removed from list

### Refresh Metadata (if metadata URL configured)

1. Edit an IdP that has a metadata URL
2. Click "Refresh Now"
3. **Verify:** Metadata is fetched and updated
4. **Verify:** "Last synced" timestamp updates

---

## Test Case 3: Error Scenarios

### Invalid SAML Response

1. Configure samling to send an invalid response
2. Attempt SSO login
3. **Verify:** `saml_error.html` displays with "Invalid SSO Response"

### Expired Response

1. Configure samling to send an expired assertion
2. Attempt SSO login
3. **Verify:** Error page shows "Response Expired"

### User Not Found

1. Ensure the email from the IdP doesn't exist in the system
2. Ensure JIT provisioning is disabled
3. Attempt SSO login
4. **Verify:** Error page shows "Account Not Found"

### Disabled IdP

1. Disable an IdP
2. Directly navigate to `/saml/login/{idp_id}`
3. **Verify:** Error page shows "Identity Provider Disabled"

### Signature Verification Failure

1. Configure IdP with wrong certificate (mismatch)
2. Attempt SSO login
3. **Verify:** Error page shows "Signature Verification Failed"

---

## Test Case 4: Import from Metadata URL

1. Navigate to `/admin/identity-providers/new`
2. In the "Quick Import" section, enter:
   - **Metadata URL:** Your IdP's metadata endpoint
   - **Provider Type:** Select appropriate type
   - **Name:** Give it a name
3. Click "Import"
4. **Verify:** IdP created with entity ID, SSO URL, and certificate auto-populated
5. **Verify:** Metadata URL is stored for future refresh

---

## Test Case 5: Multiple IdPs

1. Create two or more IdPs and enable them
2. Log out and go to login page
3. Click "Sign in with SSO"
4. **Verify:** IdP selection page (`/saml/select`) is displayed
5. **Verify:** All enabled IdPs are listed
6. **Verify:** Default IdP is marked with badge
7. Select an IdP and complete login
8. **Verify:** Correct IdP is used for authentication

---

## Test Case 6: Platform MFA Requirement

1. Edit an IdP and enable "Require Platform MFA"
2. Save changes
3. Log out and sign in via SAML
4. **Verify:** After SAML auth, redirected to `/mfa/verify`
5. Complete MFA verification
6. **Verify:** Session created after MFA completion

---

## Routes Reference

| Route | Method | Description |
|-------|--------|-------------|
| `/saml/metadata` | GET | SP metadata XML (public) |
| `/saml/login/{idp_id}` | GET | Initiate SAML login |
| `/saml/acs/{idp_id}` | POST | Assertion Consumer Service |
| `/saml/select` | GET | IdP selection page |
| `/admin/identity-providers` | GET | List IdPs (super admin) |
| `/admin/identity-providers/new` | GET/POST | Create IdP |
| `/admin/identity-providers/{id}` | GET/POST | Edit IdP |
| `/admin/identity-providers/{id}/toggle` | POST | Enable/disable |
| `/admin/identity-providers/{id}/set-default` | POST | Set as default |
| `/admin/identity-providers/{id}/delete` | POST | Delete IdP |
| `/admin/identity-providers/{id}/refresh-metadata` | POST | Refresh from URL |
| `/admin/identity-providers/import-metadata` | POST | Import from URL |

---

## API Endpoints

For programmatic testing, see `/api/v1/saml/*` endpoints:

- `GET /api/v1/saml/idps` - List IdPs
- `POST /api/v1/saml/idps` - Create IdP
- `GET /api/v1/saml/idps/{id}` - Get IdP details
- `PATCH /api/v1/saml/idps/{id}` - Update IdP
- `DELETE /api/v1/saml/idps/{id}` - Delete IdP
- `POST /api/v1/saml/idps/{id}/enable` - Enable IdP
- `POST /api/v1/saml/idps/{id}/disable` - Disable IdP
- `POST /api/v1/saml/idps/{id}/set-default` - Set default
- `POST /api/v1/saml/idps/import` - Import from metadata
- `POST /api/v1/saml/idps/{id}/refresh` - Refresh metadata
- `GET /api/v1/saml/sp/certificate` - Get SP certificate info
- `GET /api/v1/saml/sp/metadata` - Get SP metadata info
