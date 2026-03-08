# Codebase Baseline Snapshot

**Date:** 2025-11-16
**Purpose:** Point-in-time snapshot of codebase state before API implementation
**Context:** Reference for API-First Architecture implementation

---

## Overview

This document captures the state of the codebase before implementing the RESTful API layer. It serves as a baseline reference for understanding design decisions and integration points.

**Current State:**
- Multi-tenant identity platform
- Session-based authentication with mandatory MFA
- Server-side rendered pages (Jinja2 templates)
- 90% test coverage
- PostgreSQL with Row-Level Security (RLS)
- ~4,245 lines of Python code in `app/`

---

## Current Routing Structure

All current endpoints return HTML responses. No JSON API endpoints exist.

### Authentication Router (`app/routers/auth.py`)
**Prefix:** `""` (root)
**Tag:** `auth`

| Method | Path | Purpose | Auth Required |
|--------|------|---------|---------------|
| GET | `/login` | Login page | No |
| POST | `/login` | Login form submission | No |
| POST | `/logout` | Logout handler | Yes |
| GET | `/verify-email/{email_id}/{nonce}` | Email verification (public) | No |
| GET | `/set-password` | Set password page (new users) | No |
| POST | `/set-password` | Set password submission | No |
| GET | `/dashboard` | Dashboard page | Yes |

### MFA Router (`app/routers/mfa.py`)
**Prefix:** `/mfa`
**Tag:** `mfa`

| Method | Path | Purpose | Auth Required |
|--------|------|---------|---------------|
| GET | `/mfa/verify` | MFA verification page | Partial (pending) |
| POST | `/mfa/verify` | MFA verification submission | Partial |
| POST | `/mfa/verify/send-email` | Send email OTP fallback | Partial |

### Account Router (`app/routers/account.py`)
**Prefix:** `/account`
**Tag:** `account`
**Auth:** All endpoints require authenticated user

| Method | Path | Purpose | Role Required |
|--------|------|---------|---------------|
| GET | `/account/` | Redirect to first accessible page | User |
| GET | `/account/profile` | Profile settings page | User |
| POST | `/account/profile` | Update profile | User |
| POST | `/account/profile/update-timezone` | Update timezone | User |
| POST | `/account/profile/update-regional` | Update timezone & locale | User |
| GET | `/account/emails` | Email management page | User |
| POST | `/account/emails/add` | Add email | User |
| POST | `/account/emails/set-primary/{email_id}` | Set primary email | User |
| POST | `/account/emails/delete/{email_id}` | Delete email | User |
| POST | `/account/emails/resend-verification/{email_id}` | Resend verification | User |
| GET | `/account/emails/verify/{email_id}/{nonce}` | Verify email | User |
| GET | `/account/mfa` | MFA settings page | User |
| GET | `/account/mfa/setup/totp` | TOTP setup page | User |
| POST | `/account/mfa/setup/totp` | TOTP setup handler | User |
| POST | `/account/mfa/setup/email` | Enable email MFA | User |
| POST | `/account/mfa/setup/verify` | Verify TOTP setup | User |
| POST | `/account/mfa/regenerate-backup-codes` | Regenerate backup codes | User |
| POST | `/account/mfa/generate-backup-codes` | Generate initial backup codes | User |
| GET | `/account/mfa/downgrade-verify` | MFA downgrade verification page | User |
| POST | `/account/mfa/downgrade-verify` | Complete MFA downgrade | User |

### Settings Router (`app/routers/settings.py`)
**Prefix:** `/settings`
**Tag:** `settings`
**Auth:** Admin or Super Admin required

| Method | Path | Purpose | Role Required |
|--------|------|---------|---------------|
| GET | `/settings/` | Redirect to first accessible page | Admin |
| GET | `/settings/privileged-domains` | Privileged domains management | Admin |
| POST | `/settings/privileged-domains/add` | Add privileged domain | Admin |
| POST | `/settings/privileged-domains/delete/{domain_id}` | Delete privileged domain | Admin |
| GET | `/settings/tenant-security` | Tenant security settings | Super Admin |
| POST | `/settings/tenant-security/update` | Update tenant security | Super Admin |

### Users Router (`app/routers/users.py`)
**Prefix:** `/users`
**Tag:** `users`
**Auth:** Authenticated user (specific endpoints require admin)

| Method | Path | Purpose | Role Required |
|--------|------|---------|---------------|
| GET | `/users/` | Redirect to first accessible page | User |
| GET | `/users/list` | Users list (pagination/sort/search) | User |
| GET | `/users/new` | New user form | Admin |
| POST | `/users/new` | Create new user | Admin |
| GET | `/users/{user_id}` | User detail page | Admin |
| POST | `/users/{user_id}/update-name` | Update user name | Admin |
| POST | `/users/{user_id}/update-role` | Update user role | Super Admin |
| POST | `/users/{user_id}/add-email` | Add email to user | Admin |
| POST | `/users/{user_id}/remove-email/{email_id}` | Remove email from user | Admin |
| POST | `/users/{user_id}/promote-email/{email_id}` | Promote email to primary | Admin |

### Tenants Router (`app/routers/tenants.py`)
**Prefix:** `""` (root)
**Tag:** `tenants`

| Method | Path | Purpose | Auth Required |
|--------|------|---------|---------------|
| GET | `/` | Root redirect (based on auth state) | No |

---

## Authentication System

### Current Implementation: Session-Based

**Middleware:**
- `DynamicSessionMiddleware` (custom, extends Starlette's `SessionMiddleware`)
- Server-side session storage
- Configurable `max_age` per tenant
- Secret key: Derived from `SECRET_KEY` via HKDF (`utils/crypto.py`)

**Session Data:**
```python
{
    "user_id": str,              # Authenticated user ID
    "session_start": int,        # Unix timestamp
    "_max_age": int,            # Custom max_age for session
    # Temporary MFA state (during login):
    "pending_mfa_user_id": str,
    "pending_mfa_method": str,
    "pending_timezone": str,
    "pending_locale": str
}
```

### Authentication Flow

1. **Login**: `POST /login`
   - User submits email/password
   - `verify_login()` validates credentials (Argon2 password hashing)
   - Session stores `pending_mfa_user_id`
   - Redirect to MFA verification

2. **MFA Verification**: `POST /mfa/verify`
   - Validates TOTP, email OTP, or backup code
   - Session updated with `user_id` and `session_start`
   - MFA is **mandatory** for all users

3. **Session Validation**:
   - Tenant security settings control timeout
   - `session_timeout_seconds`: Max session duration
   - `persistent_sessions`: Whether sessions persist across browser close

### Authorization

**Dependency Functions** (`app/dependencies.py`):
- `get_current_user()` → Returns user dict or None
- `require_current_user()` → Redirects to `/login` if not authenticated
- `require_admin()` → Requires `admin` or `super_admin` role
- `require_super_admin()` → Requires `super_admin` role

**Roles** (PostgreSQL ENUM):
- `member` - Regular user
- `admin` - Tenant administrator
- `super_admin` - Full tenant control

**Page-Level Permissions** (`app/pages.py`):
- Central registry of all pages and their access requirements
- `has_page_access(user, page_id)` validates access
- Ensures navigational integrity (users only see accessible links)

### Multi-Factor Authentication (MFA)

**Mandatory for all users**

**Methods:**
- **TOTP** (Time-based One-Time Password) - Authenticator apps
- **Email OTP** - Time-limited codes sent via email
- **Backup Codes** - Single-use emergency codes

**Implementation:**
- TOTP secrets: Encrypted with key derived from `SECRET_KEY` via HKDF (`utils/crypto.py`)
- Email OTP codes: SHA-256 hashed, time-limited
- Backup codes: SHA-256 hashed, single-use

**Database Tables:**
- `mfa_totp` - Encrypted TOTP secrets
- `mfa_email_codes` - Hashed email OTP codes
- `mfa_backup_codes` - Hashed backup codes

### Password Security

- **Hashing**: Argon2-CFFI
- **Minimum Length**: 8 characters
- **Password-less Users**: Supported (new user invitations, set via email verification)

---

## Database Structure

### Connection & Multi-Tenancy

**Database:** PostgreSQL
**Driver:** psycopg3 with connection pooling (`psycopg-pool`)
**Isolation:** Row-Level Security (RLS) enforced via `SET LOCAL app.tenant_id`

**Core Database Layer** (`app/database/_core.py`):
```python
# All queries automatically scoped by tenant_id
with get_connection(tenant_id) as conn:
    # RLS enforced: SET LOCAL app.tenant_id = '<tenant_id>'
    conn.execute(...)
```

### Tables & Modules

#### Tenants (`app/database/tenants.py`)
**Table:** `tenants`

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    subdomain TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

**Purpose:** Tenant registry for subdomain-based routing
**RLS:** Disabled (needed for subdomain lookup)

#### Users (`app/database/users.py`)
**Table:** `users`

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP,
    password_hash TEXT,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_method TEXT,
    tz TEXT NOT NULL DEFAULT 'UTC',
    locale TEXT NOT NULL DEFAULT 'en'
);
```

**Operations:**
- CRUD operations
- Authentication (`verify_login`)
- Profile updates
- Role management
- Timezone/locale settings

**RLS Policy:** `users_tenant_isolation`

#### User Emails (`app/database/user_emails.py`)
**Table:** `user_emails`

```sql
CREATE TABLE user_emails (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email CITEXT UNIQUE NOT NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMP,
    verify_nonce TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- One primary email per user
CREATE UNIQUE INDEX user_emails_primary_unique
ON user_emails (user_id) WHERE is_primary = TRUE;
```

**Operations:**
- Add/verify/delete emails
- Primary email management
- Verification nonce generation

**RLS Policy:** `user_emails_tenant_isolation`

#### MFA (`app/database/mfa.py`)

**Tables:**

1. **`mfa_totp`** - TOTP secrets
   - `user_id`, `encrypted_secret`, `verified`, `created_at`

2. **`mfa_email_codes`** - Email OTP codes
   - `user_id`, `code_hash`, `expires_at`, `created_at`

3. **`mfa_backup_codes`** - Backup codes
   - `user_id`, `code_hash`, `used_at`, `created_at`

**Operations:**
- Enable/disable MFA
- TOTP setup and verification
- Email OTP generation and verification
- Backup code generation and verification

#### Security Settings (`app/database/security.py`)
**Table:** `tenant_security_settings`

```sql
CREATE TABLE tenant_security_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    session_timeout_seconds INTEGER NOT NULL DEFAULT 3600,
    persistent_sessions BOOLEAN NOT NULL DEFAULT TRUE,
    allow_users_edit_profile BOOLEAN NOT NULL DEFAULT TRUE,
    allow_users_add_emails BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

**Purpose:** Tenant-wide security policies

#### Settings (`app/database/settings.py`)
**Table:** `tenant_privileged_domains`

```sql
CREATE TABLE tenant_privileged_domains (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    domain TEXT NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, domain)
);
```

**Purpose:** Auto-verify emails from trusted domains

### Database Migrations

**Location:** `db-init/`
**Current Migration:** `00008_*.sql` (8 migrations total)
**Pattern:** Sequential numbered migrations

---

## Dependencies

### Production Dependencies (`pyproject.toml`)

```toml
python = "^3.12"
fastapi = "^0.115.0"          # API framework
uvicorn = "^0.32.0"           # ASGI server
psycopg = "^3.2.0"            # PostgreSQL adapter
psycopg-pool = "^3.2.0"       # Connection pooling
argh = "^0.31.0"              # CLI framework
argon2-cffi = "^23.1.0"       # Password hashing
jinja2 = "^3.1.0"             # Template engine
python-multipart = "^0.0.9"   # Form parsing
itsdangerous = "^2.2.0"       # Session signing
pyotp = "^2.9.0"              # TOTP generation/verification
cryptography = "^41.0.0"      # MFA secret encryption
babel = "^2.17.0"             # Internationalization
```

### Development Dependencies

```toml
pytest = "^8.3.0"             # Test framework
pytest-asyncio = "^0.24.0"    # Async test support
httpx = "^0.27.0"             # Async HTTP client for testing
black = "^24.10.0"            # Code formatter
ruff = "^0.7.0"               # Linter
mypy = "^1.13.0"              # Type checker
pytest-cov = "^7.0.0"         # Coverage reporting
```

### Notable Absences (for API implementation)

❌ No JWT libraries (`python-jose`, `pyjwt`)
❌ No OAuth2 libraries beyond FastAPI built-ins
✅ Argon2 already available for token hashing
✅ FastAPI has OAuth2 utilities built-in

---

## Application Structure

### Entry Point (`app/main.py`)

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Loom")
app.add_middleware(
    DynamicSessionMiddleware,
    secret_key=derive_session_key()
)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Route registration
app.include_router(auth.router)
app.include_router(mfa.router)
app.include_router(account_router.router)
app.include_router(settings_router.router)
app.include_router(tenants.router)
app.include_router(users.router)
```

**Current Response Types:**
- `HTMLResponse` (via Jinja2 templates)
- `RedirectResponse`
- `PlainTextResponse` (rare)

**No JSON responses** - Everything is server-side rendered

### Template System

**Engine:** Jinja2
**Location:** `templates/` directory
**Pattern:** One template per page

**Template Utilities:**
- `has_page_access(user, page_id)` - Authorization checks
- Timezone-aware date formatting (Babel)
- Locale-aware text (Babel)

### Static Files

**Location:** `static/` directory
**Served at:** `/static/*`
**Contents:** CSS, JavaScript, images

---

## Testing Infrastructure

### Test Framework

**Framework:** pytest
**Config:** `pytest.ini`
**Coverage:** 90% (tracked in `.coveragerc`)

### Test Database

**Connection:** `localhost:5432`
**User:** `appuser` (non-superuser to enforce RLS)
**Approach:** Each test gets isolated tenant

### Core Fixtures (`tests/conftest.py`)

```python
@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient for HTTP requests"""

@pytest.fixture
def test_subdomain() -> str:
    """Test subdomain ('dev')"""

@pytest.fixture
def test_host() -> str:
    """Test host header"""

@pytest.fixture
def test_tenant(test_subdomain):
    """Create isolated test tenant with cleanup"""

@pytest.fixture
def test_user(test_tenant):
    """Create test user (member role)"""

@pytest.fixture
def test_admin_user(test_tenant):
    """Create admin user"""

@pytest.fixture
def test_super_admin_user(test_tenant):
    """Create super_admin user"""
```

### Test Organization

**Test Files:** 24 modules

**Categories:**
1. **API Tests** (`test_api.py`) - Basic endpoint tests
2. **Authentication** (`test_auth_coverage.py`) - Auth edge cases
3. **Database Layer** (`test_database_*.py`) - 7 modules for DB operations
4. **Dependencies** (`test_dependencies.py`) - Dependency injection
5. **Middleware** (`test_middleware_session.py`) - Session handling
6. **Page Access** (`test_pages.py`) - Authorization
7. **Routers** (`test_routers_*.py`) - 5 modules for endpoint tests
8. **Utilities** (`test_utils_*.py`) - 7 modules for utility functions

### Test Patterns

**Isolation:**
- Each test creates own tenant
- Database transactions with RLS enforcement
- Cleanup after each test

**Authentication Testing:**
- Login via TestClient
- Session cookie management
- Role-based access tests

**Coverage Requirements:**
- 90% minimum coverage
- Branch coverage enabled
- CI/CD enforcement

---

## Code Metrics

### Size
- **Total Python Lines**: ~4,245 lines in `app/`
- **Test Lines**: Extensive test suite
- **Documentation**: Inline docstrings

### Code Quality
- **Type Hints**: Used throughout
- **Linting**: Ruff configured
- **Formatting**: Black configured
- **Type Checking**: mypy configured

### Architecture Patterns
- **Separation of Concerns**: Clear router/database/utility separation
- **Dependency Injection**: FastAPI dependencies for auth
- **Template Rendering**: Jinja2 for HTML
- **Database Abstraction**: Centralized database layer

---

## Current Limitations (Pre-API)

### No JSON APIs
- All endpoints return HTML
- No RESTful API structure
- No API versioning
- No JSON request/response validation

### No Token-Based Authentication
- Session cookies only
- No Bearer token support
- No OAuth2 flows
- No API keys

### No API Documentation
- No OpenAPI spec exposure
- No `/docs` endpoint
- No Pydantic request/response models

### No External Integration Support
- Can't integrate with external services
- No B2B client support
- No programmatic access
- Browser-only access

---

## Strengths (To Preserve)

### Security
✅ Argon2 password hashing
✅ Encrypted MFA secrets
✅ Row-Level Security (RLS)
✅ Session timeouts configurable
✅ Mandatory MFA

### Architecture
✅ Clean separation of concerns
✅ Multi-tenant from ground up
✅ Type-safe codebase
✅ Comprehensive test coverage
✅ Database transaction management

### User Experience
✅ Timezone-aware
✅ Locale support
✅ Email verification flow
✅ MFA with multiple methods
✅ Profile management

---

## Integration Points for API Implementation

### Where APIs Will Hook In

1. **Authentication Layer** (`app/dependencies.py`)
   - Add `get_current_user_api()` for Bearer token support
   - Reuse existing user dict structure

2. **Database Layer** (`app/database/*`)
   - Leverage existing CRUD operations
   - Add OAuth2 token operations
   - No changes to existing tables (new tables only)

3. **Routing** (`app/main.py`)
   - Add new `/api/v1/*` routes
   - Keep existing HTML routes unchanged
   - Add `/oauth2/*` routes for OAuth2 flows

4. **Testing** (`tests/`)
   - Extend existing fixtures
   - Add API-specific test modules
   - Maintain 90%+ coverage

5. **OpenAPI**
   - FastAPI auto-generates spec
   - Configure at `app/main.py`
   - Expose at `/openapi.json` and `/docs`

---

## Summary

**Current State:**
- Mature session-based authentication system
- Multi-tenant with RLS enforcement
- Server-side rendered pages only
- 90% test coverage
- Production-ready security (Argon2, MFA, encryption)

**Ready for API Layer:**
- Clean architecture supports parallel API development
- Database layer can be reused directly
- Authentication can be extended (not replaced)
- Testing infrastructure supports API tests
- No breaking changes needed to existing functionality

**Next Step:** Implement API-First Architecture per `docs/api-implementation-plan.md`

---

**Document End** - Snapshot taken 2025-11-16
