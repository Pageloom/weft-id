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

## Red Flags

| Pattern | Example | Violation |
|---------|---------|-----------|
| No tracking | `def get_something(requesting_user):` without `track_activity()` | Activity Logging |
| No event | Mutation without `log_event()` | Activity Logging |
| Event before mutation | `log_event()` then `database.update()` | Activity Logging |
| Missing tenant filter | `SELECT * FROM users WHERE email = %s` | Tenant Isolation |
| Router imports database | `from database import users` | Architecture |
| No API coverage | Service operation only in web router | API-First |

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

**Per Router Module:**
- [ ] No `from database import` statements
- [ ] Route registered in `app/pages.py`
- [ ] Service functions enforce authorization

## Event Context Note

Request context (IP, user agent, device, session) is handled automatically by `RequestContextMiddleware`. You do NOT need to check for explicit `request_metadata` passing.
