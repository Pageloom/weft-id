# API-First Architecture: Implementation Plan

This document provides a detailed implementation plan for the **API-First Architecture** backlog item.

## Overview

Implement a comprehensive RESTful API layer with OAuth2 authentication and OpenAPI specification. The API will support **three authentication methods**:
- **Session cookie authentication** for browser-based access
- **OAuth2 Authorization Code Flow** for user-delegated access (3-way: tenant ↔ user ↔ external app)
- **OAuth2 Client Credentials Flow** for B2B integrations (2-way: tenant ↔ external tenant)

All tokens are **opaque database-backed tokens** (not JWTs) for instant revocation capability.

---

## OAuth2 Design

### Client Types

**1. Normal OAuth2 Client**
- `client_type = 'normal'`
- **Allowed flows**: Authorization Code Flow ONLY
- **Authentication**: Can authenticate any user in the same tenant
- **Token grants**: User authorizes, token acts AS that user (inherits user's permissions)
- **No scopes**: Access is determined by the user's role
- **Configuration**: Name, redirect URIs (exact match only)
- **Use case**: "Slack Integration", "Mobile App", "Analytics Dashboard"

**2. B2B OAuth2 Client**
- `client_type = 'b2b'`
- **Allowed flows**: Client Credentials Flow ONLY
- **Authentication**: Hard-wired to a specific service user
- **Token grants**: Token always acts AS the service user
- **Service user**: Automatically created with `first_name = client_name`, configurable role
- **Configuration**: Name, role (member/admin/super_admin)
- **Use case**: "HR System", "Provisioning Service", "External IdP Sync"
- **Lifecycle**: Service user and B2B client are coupled - deleting one affects the other

### Token Types & Expiry

| Token Type | Expiry | Renewable | Purpose |
|------------|--------|-----------|---------|
| Authorization Code | 5 minutes | No | Exchange for access token |
| Access Token (auth code) | 1 hour | Via refresh | User-delegated API access |
| Refresh Token | 30 days | No | Renew access token |
| Access Token (client creds) | 24 hours | Request new | B2B API access |

All tokens are:
- **Opaque** (random strings, not JWTs)
- **Hashed** before storage (using Argon2)
- **Database-backed** (can be instantly revoked)

### PKCE Support

**Proof Key for Code Exchange (RFC 7636)**
- **Support**: Optional (not required)
- **Methods**: S256 (SHA-256) and plain
- **Purpose**: Prevents authorization code interception attacks
- **Required for**: Mobile apps, SPAs, any public client

---

## Database Schema

### `oauth2_clients`

```sql
CREATE TABLE oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    client_type TEXT NOT NULL CHECK (client_type IN ('normal', 'b2b')),
    name TEXT NOT NULL,
    redirect_uris TEXT[], -- NULL for b2b clients
    service_user_id UUID REFERENCES users(id) ON DELETE RESTRICT, -- NULL for normal clients
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth2_clients_tenant ON oauth2_clients(tenant_id);
CREATE INDEX idx_oauth2_clients_service_user ON oauth2_clients(service_user_id) WHERE service_user_id IS NOT NULL;

-- RLS policy for tenant isolation
ALTER TABLE oauth2_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_clients_tenant_isolation ON oauth2_clients
    USING (tenant_id::text = current_setting('app.tenant_id', true));
```

**Fields:**
- `client_id`: Public identifier (e.g., `loom_client_abc123`)
- `client_secret_hash`: Argon2 hash of client secret
- `client_type`: `'normal'` or `'b2b'`
- `redirect_uris`: Array of exact redirect URIs (normal clients only)
- `service_user_id`: Links to service user (B2B clients only)

**Constraints:**
- Service user deletion is RESTRICTED (must delete client first)
- This forces explicit decision-making when removing B2B integrations

### `oauth2_authorization_codes`

```sql
CREATE TABLE oauth2_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    code_hash TEXT UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT, -- for PKCE
    code_challenge_method TEXT CHECK (code_challenge_method IN ('S256', 'plain')),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth2_codes_tenant ON oauth2_authorization_codes(tenant_id);
CREATE INDEX idx_oauth2_codes_expires ON oauth2_authorization_codes(expires_at);

-- RLS policy
ALTER TABLE oauth2_authorization_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_codes_tenant_isolation ON oauth2_authorization_codes
    USING (tenant_id::text = current_setting('app.tenant_id', true));
```

**Fields:**
- `code_hash`: Argon2 hash of authorization code
- `code_challenge`: PKCE code challenge (optional)
- `code_challenge_method`: `'S256'` or `'plain'` (optional)
- `redirect_uri`: Must match exactly during token exchange

**Lifecycle:**
- Very short-lived (5 minutes)
- One-time use (deleted after exchange)
- Auto-cleanup of expired codes

### `oauth2_tokens`

```sql
CREATE TABLE oauth2_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_hash TEXT UNIQUE NOT NULL,
    token_type TEXT NOT NULL CHECK (token_type IN ('access', 'refresh')),
    client_id UUID NOT NULL REFERENCES oauth2_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    parent_token_id UUID REFERENCES oauth2_tokens(id) ON DELETE CASCADE -- access tokens link to refresh token
);

CREATE INDEX idx_oauth2_tokens_tenant ON oauth2_tokens(tenant_id);
CREATE INDEX idx_oauth2_tokens_user ON oauth2_tokens(user_id);
CREATE INDEX idx_oauth2_tokens_expires ON oauth2_tokens(expires_at);
CREATE INDEX idx_oauth2_tokens_hash ON oauth2_tokens(token_hash); -- for fast lookups

-- RLS policy
ALTER TABLE oauth2_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth2_tokens_tenant_isolation ON oauth2_tokens
    USING (tenant_id::text = current_setting('app.tenant_id', true));
```

**Fields:**
- `token_hash`: Argon2 hash of opaque token
- `token_type`: `'access'` or `'refresh'`
- `user_id`: The user this token acts as
- `parent_token_id`: For access tokens, links to the refresh token that created it

**Cascade Behavior:**
- Deleting a refresh token deletes all its access tokens
- Deleting a client deletes all its tokens
- Deleting a user deletes all their tokens

---

## Phase 1: OAuth2 Infrastructure & Core Authentication (Week 1)

### Step 1: Add Dependencies

Update `pyproject.toml`:
```toml
# No new dependencies needed!
# We're using opaque tokens, not JWTs
# Argon2 already available for hashing
# FastAPI already has OAuth2 utilities
```

### Step 2: Database Migration (`db-init/00009_oauth2.sql`)

Create all three tables:
- `oauth2_clients`
- `oauth2_authorization_codes`
- `oauth2_tokens`

Include:
- RLS policies for tenant isolation
- Indexes for performance
- Cascade delete rules
- Check constraints

### Step 3: OAuth2 Core Module (`app/oauth2.py`)

**Token utilities:**
```python
def generate_opaque_token(prefix: str = "loom") -> str:
    """Generate cryptographically secure random token"""

def hash_token(token: str) -> str:
    """Hash token with Argon2 (same as passwords)"""

def verify_token_hash(token: str, token_hash: str) -> bool:
    """Verify token against stored hash"""
```

**PKCE utilities:**
```python
def verify_pkce_challenge(
    code_verifier: str,
    code_challenge: str,
    method: str
) -> bool:
    """Verify PKCE code challenge"""
```

**Constants:**
```python
AUTHORIZATION_CODE_EXPIRY = timedelta(minutes=5)
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)
CLIENT_CREDENTIALS_TOKEN_EXPIRY = timedelta(hours=24)
```

### Step 4: OAuth2 Database Layer (`app/database/oauth2.py`)

**Client operations:**
- `create_normal_client(tenant_id, name, redirect_uris, created_by) -> dict`
- `create_b2b_client(tenant_id, name, role, created_by) -> dict`
  - Creates service user first
  - Links client to service user
  - Returns client details + client_secret (plain text, shown once)
- `get_client_by_client_id(tenant_id, client_id) -> dict | None`
- `delete_client(tenant_id, client_id)`
- `regenerate_client_secret(tenant_id, client_id) -> str`

**Authorization code operations:**
- `create_authorization_code(tenant_id, client_id, user_id, redirect_uri, code_challenge, code_challenge_method) -> str`
- `validate_and_consume_code(tenant_id, code_hash, client_id, redirect_uri, code_verifier) -> dict | None`
- `cleanup_expired_codes()`

**Token operations:**
- `create_access_token(tenant_id, client_id, user_id, parent_token_id=None) -> str`
- `create_refresh_token(tenant_id, client_id, user_id) -> str`
- `validate_token(token: str) -> dict | None` (returns user_id, tenant_id, expires_at)
- `revoke_token(token_hash)`
- `revoke_all_client_tokens(client_id)`
- `cleanup_expired_tokens()`

### Step 5: OAuth2 Endpoints (`app/routers/oauth2.py`)

**Authorization endpoints:**

**`GET /oauth2/authorize`**
- Query params: `client_id`, `redirect_uri`, `state`, `code_challenge` (optional), `code_challenge_method` (optional)
- Requires: User logged in (session cookie)
- Validates: Client exists, client_type='normal', redirect_uri matches exactly
- Response: HTML authorization page "Allow [Client Name] to access your account?"

**`POST /oauth2/authorize`**
- Form data: `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, `action` ('allow' or 'deny')
- Validates: Same as GET
- If allowed: Create authorization code, redirect to `redirect_uri?code=...&state=...`
- If denied: Redirect to `redirect_uri?error=access_denied&state=...`

**Token endpoint:**

**`POST /oauth2/token`**

Multiple grant types supported:

**Grant type: `authorization_code`**
- Request: `grant_type`, `code`, `client_id`, `client_secret`, `redirect_uri`, `code_verifier` (if PKCE)
- Validates:
  - Client credentials
  - Authorization code (not expired, matches client, matches redirect_uri)
  - PKCE code_verifier (if code_challenge was provided)
- Response: `{access_token, refresh_token, token_type: "Bearer", expires_in: 3600}`
- Side effects: Delete authorization code (one-time use)

**Grant type: `refresh_token`**
- Request: `grant_type`, `refresh_token`, `client_id`, `client_secret`
- Validates: Client credentials, refresh token valid and not expired
- Response: `{access_token, token_type: "Bearer", expires_in: 3600}`

**Grant type: `client_credentials`**
- Request: `grant_type`, `client_id`, `client_secret`
- Validates: Client credentials, client_type='b2b'
- Response: `{access_token, token_type: "Bearer", expires_in: 86400}`
- Note: No refresh token (just request a new one)

### Step 6: Dual Authentication Dependency (`app/api_dependencies.py`)

```python
async def get_current_user_api(
    request: Request,
    authorization: str | None = Header(None, alias="Authorization")
) -> dict:
    """
    Accepts EITHER:
    - Bearer token in Authorization header
    - Session cookie

    Returns user dict or raises HTTPException 401
    """
    # Try Bearer token first
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        token_data = validate_token(token)  # DB lookup
        if token_data and token_data['expires_at'] > datetime.now():
            # Get user from token's user_id
            user = get_user_by_id(token_data['tenant_id'], token_data['user_id'])
            if user:
                return user

    # Fall back to session cookie
    user = get_current_user(request)
    if user:
        return user

    raise HTTPException(status_code=401, detail="Not authenticated")

def require_admin_api(user: dict = Depends(get_current_user_api)) -> dict:
    """Admin or super_admin required"""
    if user['role'] not in ['admin', 'super_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def require_super_admin_api(user: dict = Depends(get_current_user_api)) -> dict:
    """Super admin required"""
    if user['role'] != 'super_admin':
        raise HTTPException(status_code=403, detail="Super admin access required")
    return user
```

### Step 7: OAuth2 Client Management API (`app/routers/api/v1/oauth2_clients.py`)

**Pydantic Models:**
```python
class NormalClientCreate(BaseModel):
    name: str
    redirect_uris: list[str]

class B2BClientCreate(BaseModel):
    name: str
    role: str  # 'member', 'admin', 'super_admin'

class ClientResponse(BaseModel):
    id: str
    client_id: str
    client_type: str
    name: str
    redirect_uris: list[str] | None
    service_user_id: str | None
    created_at: datetime

class ClientWithSecret(ClientResponse):
    client_secret: str  # Only returned on creation
```

**Endpoints:**

**`GET /api/v1/oauth2/clients`**
- Auth: Admin required
- Response: List of all OAuth2 clients for the tenant
- Includes service user info for B2B clients

**`POST /api/v1/oauth2/clients`**
- Auth: Admin required
- Request: `NormalClientCreate`
- Response: `ClientWithSecret` (client_secret shown only once!)
- Creates normal OAuth2 client

**`POST /api/v1/oauth2/clients/b2b`**
- Auth: Admin required
- Request: `B2BClientCreate`
- Response: `ClientWithSecret`
- Creates:
  1. Service user with `first_name=name`, specified role
  2. B2B OAuth2 client linked to service user

**`DELETE /api/v1/oauth2/clients/{client_id}`**
- Auth: Admin required
- Deletes client and all associated tokens
- For B2B clients: Service user remains (admin must delete separately if desired)

**`POST /api/v1/oauth2/clients/{client_id}/regenerate-secret`**
- Auth: Admin required
- Generates new client_secret, invalidates old one
- Response: New `client_secret` (shown once)

### Step 8: First API Endpoints (`app/routers/api/v1/users.py`)

**`GET /api/v1/users/me`**
- Auth: Any authenticated user (cookie or Bearer)
- Response: Current user profile
- Works with:
  - Session cookie
  - OAuth2 access token (normal client)
  - OAuth2 access token (B2B client - returns service user)

**`PATCH /api/v1/users/me`**
- Auth: Any authenticated user
- Request: `{first_name?, last_name?, timezone?, locale?}`
- Response: Updated user profile

**Pydantic Models:**
```python
class UserProfile(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    timezone: str
    locale: str
    mfa_enabled: bool
    mfa_method: str | None
    created_at: datetime
    last_login: datetime | None

class UserProfileUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    timezone: str | None = None
    locale: str | None = None
```

### Step 9: OpenAPI Configuration & Testing

**Update `app/main.py`:**
```python
app = FastAPI(
    title="Loom Identity Platform API",
    version="1.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
)

# Configure OAuth2 security schemes
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Loom Identity Platform API",
        version="1.0.0",
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2AuthorizationCode": {
            "type": "oauth2",
            "flows": {
                "authorizationCode": {
                    "authorizationUrl": "/oauth2/authorize",
                    "tokenUrl": "/oauth2/token",
                    "scopes": {}
                }
            }
        },
        "OAuth2ClientCredentials": {
            "type": "oauth2",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": "/oauth2/token",
                    "scopes": {}
                }
            }
        },
        "SessionCookie": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session"
        }
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

**Test fixtures (`tests/conftest.py`):**
```python
@pytest.fixture
def normal_oauth2_client(test_tenant, test_admin_user):
    """Create normal OAuth2 client for testing"""
    return create_normal_client(
        tenant_id=test_tenant['id'],
        name="Test Client",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=test_admin_user['id']
    )

@pytest.fixture
def b2b_oauth2_client(test_tenant, test_admin_user):
    """Create B2B OAuth2 client for testing"""
    return create_b2b_client(
        tenant_id=test_tenant['id'],
        name="Test B2B Client",
        role="admin",
        created_by=test_admin_user['id']
    )

@pytest.fixture
def user_access_token(test_tenant, normal_oauth2_client, test_user):
    """Create access token for normal client acting as user"""
    # Simulate authorization code flow
    code = create_authorization_code(...)
    token = exchange_code_for_token(...)
    return token

@pytest.fixture
def b2b_access_token(test_tenant, b2b_oauth2_client):
    """Create access token for B2B client"""
    # Simulate client credentials flow
    return create_client_credentials_token(...)
```

**Test files:**
- `tests/api/test_oauth2_authorization_code.py` - Authorization code flow tests
- `tests/api/test_oauth2_pkce.py` - PKCE flow tests
- `tests/api/test_oauth2_client_credentials.py` - Client credentials flow tests
- `tests/api/test_oauth2_clients.py` - Client management API tests
- `tests/api/test_dual_auth.py` - Cookie vs Bearer token tests

---

## Phase 2: Core API Endpoints (Week 2)

### Step 10: User Management API (`app/routers/api/v1/users.py`)

**`GET /api/v1/users`**
- Auth: Admin required
- Query params: `page`, `limit`, `search`, `sort_by`, `sort_order`
- Response: `{items: UserProfile[], total: int, page: int, limit: int}`
- Note: Service users marked with indicator

**`GET /api/v1/users/{user_id}`**
- Auth: Admin required
- Response: Detailed user profile including all emails, MFA status
- Shows if user is a service user (has associated B2B client)

**`POST /api/v1/users`**
- Auth: Admin required
- Request: `{first_name, last_name, email, role?, privileged_domain?}`
- Response: Created user
- Same logic as existing user creation

**`PATCH /api/v1/users/{user_id}`**
- Auth: Admin required (role changes: super_admin only)
- Request: `{first_name?, last_name?, role?}`
- Response: Updated user
- Validation: Cannot delete service user (shows error)

**Pydantic Models:**
```python
class UserList(BaseModel):
    items: list[UserProfile]
    total: int
    page: int
    limit: int

class UserDetail(UserProfile):
    emails: list[EmailInfo]
    is_service_user: bool  # Derived from oauth2_clients relationship

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    role: str = 'member'
    privileged_domain: str | None = None

class UserUpdate(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    role: str | None = None
```

### Step 11: Email Management API (`app/routers/api/v1/emails.py`)

**`GET /api/v1/users/me/emails`**
- Auth: Any authenticated user
- Response: List of user's emails with verification status

**`POST /api/v1/users/me/emails`**
- Auth: Any authenticated user
- Request: `{email: str}`
- Response: Created email with verification sent
- Respects tenant security settings

**`DELETE /api/v1/users/me/emails/{email_id}`**
- Auth: Any authenticated user
- Validates: Not deleting primary email, not last email

**`POST /api/v1/users/me/emails/{email_id}/set-primary`**
- Auth: Any authenticated user
- Validates: Email is verified
- Updates primary email

**`POST /api/v1/users/me/emails/{email_id}/resend-verification`**
- Auth: Any authenticated user
- Sends new verification email

**Pydantic Models:**
```python
class EmailInfo(BaseModel):
    id: str
    email: str
    is_primary: bool
    verified_at: datetime | None
    created_at: datetime

class EmailList(BaseModel):
    items: list[EmailInfo]

class EmailCreate(BaseModel):
    email: str
```

### Step 12: Settings Management API (`app/routers/api/v1/settings.py`)

**`GET /api/v1/settings/privileged-domains`**
- Auth: Admin required
- Response: List of privileged domains

**`POST /api/v1/settings/privileged-domains`**
- Auth: Admin required
- Request: `{domain: str}`
- Response: Created domain

**`DELETE /api/v1/settings/privileged-domains/{domain_id}`**
- Auth: Admin required

**`GET /api/v1/settings/security`**
- Auth: Super admin required
- Response: Tenant security settings

**`PATCH /api/v1/settings/security`**
- Auth: Super admin required
- Request: Security settings update
- Response: Updated settings

### Step 13: MFA Management API (`app/routers/api/v1/mfa.py`)

All endpoints require authenticated user (acts on current user only).

**`GET /api/v1/mfa/status`**
- Response: `{enabled: bool, method: str | null, backup_codes_remaining: int}`

**`POST /api/v1/mfa/setup/totp`**
- Response: `{secret: str, qr_uri: str, backup_codes: str[]}`
- Note: Not yet enabled, must verify first

**`POST /api/v1/mfa/setup/verify`**
- Request: `{code: str}`
- Validates TOTP code, enables MFA

**`POST /api/v1/mfa/setup/email`**
- Enables email-based MFA
- Response: `{backup_codes: str[]}`

**`POST /api/v1/mfa/backup-codes/regenerate`**
- Requires MFA verification first
- Response: New backup codes

**`POST /api/v1/mfa/downgrade`**
- Downgrade from TOTP to email MFA
- Requires MFA verification

### Step 14: Testing Phase 2

**Comprehensive test coverage:**
- All CRUD operations
- Role-based access control (member/admin/super_admin)
- Tenant isolation (users can't access other tenants)
- Service user protection (can't delete service users)
- All three auth methods work on each endpoint
- Pagination, search, sorting
- Error cases and validation

---

## Phase 3: API Testing Strategy & Documentation (Week 3)

### Step 15: Spec-Based Testing

**Approach: Custom pytest-based contract testing**

Why not schemathesis:
- More control over test scenarios
- Leverage existing fixtures
- Can test authorization flows properly

**Implementation:**

```python
# tests/api/test_openapi_contract.py

def test_all_api_endpoints_in_spec(client):
    """Ensure all implemented API endpoints are in OpenAPI spec"""
    openapi = client.get("/openapi.json").json()
    paths = openapi["paths"]

    # Get all /api/v1/* routes from FastAPI
    api_routes = [route for route in app.routes if route.path.startswith("/api/v1/")]

    # Verify all routes are documented
    for route in api_routes:
        assert route.path in paths

def test_all_responses_match_schema(client, test_user_access_token):
    """Validate response schemas match OpenAPI spec"""
    openapi = client.get("/openapi.json").json()

    # For each endpoint, make request and validate response
    for path, methods in openapi["paths"].items():
        for method, spec in methods.items():
            # Make request
            response = make_request(client, method, path, test_user_access_token)

            # Validate response schema
            assert validate_schema(response.json(), spec["responses"][str(response.status_code)])
```

### Step 16: Error Handling & Response Formatting

**Standardized error responses:**

```python
class ErrorDetail(BaseModel):
    detail: str
    error_code: str | None = None

# Example responses:
{
    "detail": "User not found",
    "error_code": "USER_NOT_FOUND"
}

{
    "detail": "Cannot delete service user. Delete associated OAuth2 client first.",
    "error_code": "SERVICE_USER_DELETE_FORBIDDEN"
}
```

**HTTP Status Codes:**
- 200 OK - Successful GET/PATCH
- 201 Created - Successful POST
- 204 No Content - Successful DELETE
- 400 Bad Request - Validation error
- 401 Unauthorized - Not authenticated
- 403 Forbidden - Authenticated but insufficient permissions
- 404 Not Found - Resource doesn't exist
- 409 Conflict - Duplicate resource (e.g., email already exists)
- 422 Unprocessable Entity - Pydantic validation error
- 500 Internal Server Error - Server error

### Step 17: Service User Protection

**Database layer:**
```python
def delete_user(tenant_id: str, user_id: str):
    # Check if user is a service user
    client = get_b2b_client_by_service_user(tenant_id, user_id)
    if client:
        raise ValueError(
            f"Cannot delete service user. "
            f"Delete OAuth2 client '{client['name']}' first."
        )

    # Proceed with deletion
    ...
```

**UI indicators:**
- User list: Badge/icon for service users
- User detail: Warning message if trying to delete
- OAuth2 client list: Show linked service user

### Step 18: Documentation & Cleanup

**OpenAPI spec enhancements:**
- Add descriptions for all endpoints
- Document OAuth2 flows with examples
- Document error responses
- Add security requirements to each endpoint

**Documentation files:**
- `docs/oauth2-authorization-code-flow.md` - Step-by-step guide
- `docs/oauth2-client-credentials-flow.md` - B2B integration guide
- `docs/api-authentication.md` - Overview of all auth methods

**CI/CD:**
- Run all API tests in GitHub Actions
- Maintain 90%+ coverage
- Spec validation on every commit

---

## Complete API Endpoint Summary

### OAuth2 & Authentication
- `GET /oauth2/authorize` - Authorization page (normal clients)
- `POST /oauth2/authorize` - Grant authorization
- `POST /oauth2/token` - Token endpoint (all grant types)
- `GET /api/v1/oauth2/clients` - List OAuth2 clients (admin)
- `POST /api/v1/oauth2/clients` - Create normal client (admin)
- `POST /api/v1/oauth2/clients/b2b` - Create B2B client (admin)
- `DELETE /api/v1/oauth2/clients/{client_id}` - Delete client (admin)
- `POST /api/v1/oauth2/clients/{client_id}/regenerate-secret` - Regenerate secret (admin)

### User Profile (Self-Service)
- `GET /api/v1/users/me` - Get profile
- `PATCH /api/v1/users/me` - Update profile

### Email Management (Self-Service)
- `GET /api/v1/users/me/emails` - List emails
- `POST /api/v1/users/me/emails` - Add email
- `DELETE /api/v1/users/me/emails/{email_id}` - Delete email
- `POST /api/v1/users/me/emails/{email_id}/set-primary` - Set primary
- `POST /api/v1/users/me/emails/{email_id}/resend-verification` - Resend verification

### MFA Management (Self-Service)
- `GET /api/v1/mfa/status` - Get MFA status
- `POST /api/v1/mfa/setup/totp` - Setup TOTP
- `POST /api/v1/mfa/setup/verify` - Verify TOTP
- `POST /api/v1/mfa/setup/email` - Enable email MFA
- `POST /api/v1/mfa/backup-codes/regenerate` - Regenerate codes
- `POST /api/v1/mfa/downgrade` - Downgrade MFA

### User Management (Admin)
- `GET /api/v1/users` - List users
- `GET /api/v1/users/{user_id}` - Get user
- `POST /api/v1/users` - Create user
- `PATCH /api/v1/users/{user_id}` - Update user

### Settings Management (Admin)
- `GET /api/v1/settings/privileged-domains` - List domains
- `POST /api/v1/settings/privileged-domains` - Add domain
- `DELETE /api/v1/settings/privileged-domains/{domain_id}` - Delete domain
- `GET /api/v1/settings/security` - Get security settings (super_admin)
- `PATCH /api/v1/settings/security` - Update security (super_admin)

---

## Key Design Decisions

✅ **Opaque tokens, not JWTs** - Database-backed for instant revocation
✅ **Three auth methods** - Session cookies, authorization code flow, client credentials flow
✅ **Two OAuth2 client types** - Normal (user delegation) vs B2B (service account)
✅ **Service users for B2B** - B2B clients act as users, use existing RBAC
✅ **No scopes** - Access determined by user's role (simple, uses existing system)
✅ **PKCE optional** - Support both PKCE and non-PKCE flows
✅ **Exact redirect URI matching** - No wildcards for security
✅ **Lifecycle coupling** - Service users protected, must delete client first
✅ **Admin-level access** - Admins can manage OAuth2 clients
✅ **Argon2 for everything** - Client secrets, tokens all use same proven hashing

---

## Deliverables

✅ Authorization Code Flow with optional PKCE
✅ Client Credentials Flow for B2B integrations
✅ Refresh token support (30 day expiry)
✅ Complete RESTful API with /api/v1/ prefix
✅ Opaque database-backed tokens (instant revocation)
✅ Service user system for B2B clients
✅ OAuth2 client management UI/API
✅ OpenAPI 3.x specification at /openapi.json
✅ Interactive OAuth2-enabled docs at /docs
✅ Dual authentication (cookies + Bearer tokens)
✅ Spec-based contract testing
✅ Comprehensive test suite
✅ 90%+ test coverage maintained
✅ Service user protection (delete prevention)
✅ All existing HTML pages remain functional
