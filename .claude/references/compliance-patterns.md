# Architectural Compliance Patterns Reference

This document contains detailed patterns and checklists for the `/compliance` agent.

## The Five Principles

### 1. Activity Tracking & Event Logging

**Rule:** "If there is a write, there is a log" - NO EXCEPTIONS

**Read Operations:**
```python
def get_user(requesting_user: RequestingUser, user_id: str) -> UserResponse:
    track_activity(requesting_user["tenant_id"], requesting_user["id"])  # REQUIRED
    user = database.users.get_user(requesting_user["tenant_id"], user_id)
    return UserResponse(**user)
```

**Write Operations:**
```python
def inactivate_user(requesting_user: RequestingUser, user_id: str) -> None:
    _require_admin(requesting_user)
    database.users.inactivate_user(requesting_user["tenant_id"], user_id)

    log_event(  # REQUIRED - after successful mutation
        tenant_id=requesting_user["tenant_id"],
        actor_user_id=requesting_user["id"],
        event_type="user_inactivated",
        artifact_type="user",
        artifact_id=user_id,
        metadata=None
    )
```

**Mutation Indicators:**
- `database.create_*()`, `database.update_*()`, `database.delete_*()`, `database.set_*()`
- Sends emails via `utils.email`
- Clears caches or invalidates sessions
- Creates/deletes files in storage

### 2. Tenant Isolation

**Rule:** All data access must be tenant-scoped

**Correct:**
```python
def get_user(tenant_id: str, user_id: str) -> dict:
    result = conn.execute(
        "SELECT * FROM users WHERE tenant_id = %s AND id = %s",
        (tenant_id, user_id)
    )
```

**Violation:**
```python
def get_user_by_email(email: str) -> dict:
    # VIOLATION: No tenant_id filter!
    result = conn.execute("SELECT * FROM users WHERE email = %s", (email,))
```

### 3. Authorization Patterns

**Route Registration** (`app/pages.py`):
```python
Page(
    path="/users/new",
    title="Add User",
    permission=PagePermission.ADMIN,
)
```

**Service Layer:**
```python
def create_user(requesting_user: RequestingUser, user_data: UserCreate):
    if user_data.role in ("admin", "super_admin") and requesting_user["role"] != "super_admin":
        raise ForbiddenError(message="Only super_admin can create admin users")
```

### 4. Service Layer Architecture

```
Request → Router → Service → Database → PostgreSQL
```

**Correct:**
```python
# app/routers/users.py
from services import users as users_service  # Import service layer

@router.post("/users")
def create_user_route(...):
    result = users_service.create_user(requesting_user, user_data)
```

**Violation:**
```python
# app/routers/users.py
from database import users as users_db  # VIOLATION: Direct database import!
```

### 5. API-First Methodology

**Rule:** All functionality must be achievable via RESTful API endpoints

**Exceptions (not violations):**
- Authentication flows (login, logout, OAuth callbacks)
- SAML ACS/SLO endpoints
- Admin UI conveniences combining multiple API operations

**Documentation:** API endpoint docstrings must accurately list all supported parameters and fields. When a PATCH/PUT endpoint accepts a schema, the docstring must document every field the schema exposes. Incomplete documentation misleads API consumers and is a compliance violation.

**Correct:**
```python
@router.patch("/{sp_id}", response_model=SPConfig)
def update_service_provider(..., sp_data: SPUpdate):
    """Update a Service Provider's configuration.

    Requires super_admin role.

    Request body (all fields optional, at least one required):
    - name: Display name
    - description: Description
    - acs_url: Assertion Consumer Service URL
    - slo_url: Single Logout URL
    - nameid_format: NameID format
    - available_to_all: Whether SP is available to all users
    - include_group_claims: Include group claims in assertion
    - attribute_mapping: Custom attribute mappings
    """
```

**Violation:**
```python
# Docstring lists only 3 of 8+ fields — misleads consumers
```

### 6. Input Length Validation

**Rule:** All `str` fields in Pydantic input schemas must have `max_length`. Database TEXT columns should have matching constraints.

**Standard limits:**

| Category | Limit | Examples |
|----------|-------|---------|
| Names/titles | 255 | user name, SP name, IdP name, tenant name |
| Descriptions | 2000 | SP description, group description |
| URLs | 2048 | entity_id, sso_url, acs_url, metadata_url |
| Enum-like | 50 | status, type, method, theme, locale |
| Subdomains | 63 | DNS label max |
| Domains | 253 | DNS max |
| IP addresses | 45 | IPv6 max |

**Correct:**
```python
class SPCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    acs_url: str = Field(max_length=2048)
```

**Violation:**
```python
class SPCreate(BaseModel):
    name: str  # VIOLATION: No max_length!
    description: str | None = None  # VIOLATION: No max_length!
```

### 8. Migration Backwards Compatibility

**Rule:** Migrations must be safe to apply on a running instance.

**Breaking (never do in a single migration):**
```sql
-- VIOLATION: breaks running code that references the column
ALTER TABLE users DROP COLUMN legacy_field;

-- VIOLATION: breaks running code that references the table
DROP TABLE old_audit_log;

-- VIOLATION: breaks running code using old name
ALTER TABLE users RENAME COLUMN name TO display_name;

-- VIOLATION: fails on non-empty tables, breaks running inserts
ALTER TABLE users ADD COLUMN role text NOT NULL;
```

**Safe alternatives:**
```sql
-- Safe: nullable column, no impact on running code
ALTER TABLE users ADD COLUMN new_field text;

-- Safe: NOT NULL with DEFAULT, existing rows get the default
ALTER TABLE users ADD COLUMN status text NOT NULL DEFAULT 'active';

-- Safe: non-blocking index creation
CREATE INDEX CONCURRENTLY idx_users_email ON users (email);
```

**Multi-step migration strategy for breaking changes:**
1. Add new column (nullable or with default)
2. Deploy code that writes to both old and new columns
3. Backfill existing data
4. Deploy code that reads from new column only
5. Drop old column in a later migration

**Suppression:** Add `-- migration-safety: ignore` on its own line to skip checks for a file:
```sql
-- migration-safety: ignore
-- This cleanup migration runs after v2.3 removed all references to legacy_field.
SET LOCAL ROLE appowner;
ALTER TABLE users DROP COLUMN legacy_field;
```

## Red Flags

| Pattern | Example | Violation |
|---------|---------|-----------|
| No tracking | `def get_something(requesting_user):` without `track_activity()` | Activity Logging |
| No event | Mutation without `log_event()` | Activity Logging |
| Event before mutation | `log_event()` then `database.update()` | Activity Logging |
| Missing tenant filter | `SELECT * FROM users WHERE email = %s` | Tenant Isolation |
| Router imports database | `from database import users` | Architecture |
| No API coverage | Service operation only in web router | API-First |
| Incomplete API docs | Docstring lists subset of accepted fields | API-First |
| No max_length | `name: str` without `Field(max_length=N)` | Input Validation |
| DROP COLUMN/TABLE | `ALTER TABLE x DROP COLUMN y` in migration | Migration Safety |
| RENAME in migration | `ALTER TABLE x RENAME COLUMN y TO z` | Migration Safety |
| NOT NULL without DEFAULT | `ADD COLUMN x text NOT NULL` (no DEFAULT) | Migration Safety |
| Non-concurrent index | `CREATE INDEX` without `CONCURRENTLY` | Migration Safety |

## Verification Checklists

**Per Service Module:**
- [ ] List all functions with `RequestingUser` parameter
- [ ] Verify reads call `track_activity()` at function start
- [ ] Verify writes call `log_event()` after mutation
- [ ] Check event_type is descriptive and past-tense

**Per Database Module:**
- [ ] All SELECT queries filter by `tenant_id`
- [ ] INSERT includes `tenant_id` column
- [ ] UPDATE/DELETE filter by `tenant_id`
- [ ] Cross-tenant queries use `UNSCOPED` with comment

**Per Schema Module (Input Models):**
- [ ] All `str` fields have `max_length` specified
- [ ] Limits follow the standard categories (names 255, descriptions 2000, URLs 2048, enums 50)
- [ ] Optional string fields also have `max_length` via `Field(default=None, max_length=N)`

**Per API Router Module:**
- [ ] Endpoint docstrings list all accepted fields/parameters
- [ ] PATCH/PUT docstrings match the schema they accept (no missing fields)

**Per Router Module:**
- [ ] No `from database import` statements
- [ ] Route registered in `app/pages.py`
- [ ] Service functions enforce authorization

## Event Context Note

Request context (IP, user agent, device, session) is handled automatically by `RequestContextMiddleware`. You do NOT need to check for explicit `request_metadata` passing.
