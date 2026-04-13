# OWASP Security Patterns Reference

This document contains detailed vulnerability patterns and checklists for the `/security` agent.

## Vulnerability Categories

### 1. SQL Injection (A03:2021)

**Red Flag:**
```python
# VULNERABLE - string formatting
query = f"SELECT * FROM users WHERE email = '{email}'"

# SAFE - parameterized
query = "SELECT * FROM users WHERE email = %s", (email,)
```

**Checklist:**
- [ ] Search for `f"` or `f'` near SQL keywords (SELECT, INSERT, UPDATE, DELETE)
- [ ] Search for `.format(` near SQL
- [ ] Check dynamic table/column names are validated against allowlists
- [ ] Review search/filter endpoints for proper wildcard escaping (`%`, `_`)

### 2. Cross-Site Scripting (A03:2021)

**Red Flag:**
```html
<!-- VULNERABLE -->
{{ user_input | safe }}

<!-- SAFE - auto-escaped -->
{{ user_input }}
```

```javascript
// VULNERABLE - innerHTML with unescaped interpolation
previewEl.innerHTML = `<p>${data.name}</p>`;

// SAFE - escapeHtml wrapper
previewEl.innerHTML = `<p>${escapeHtml(data.name)}</p>`;
```

**Checklist:**
- [ ] Search templates for `| safe` usage without justification comment
- [ ] Search templates for `innerHTML` assignments with `${` interpolation missing `escapeHtml()`
- [ ] Review JavaScript that handles user data
- [ ] Check API responses that reflect user input
- [ ] Verify CSP headers are configured

### 3. Broken Authentication (A07:2021)

**Red Flag:**
```python
# VULNERABLE - weak hashing
hashlib.md5(password.encode()).hexdigest()

# SAFE
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

**Checklist:**
- [ ] Password hashing uses bcrypt/argon2 with appropriate cost
- [ ] Session tokens use `secrets.token_urlsafe(32)` or similar
- [ ] Session regenerates on login (fixation prevention)
- [ ] Rate limiting on auth endpoints
- [ ] Password reset tokens are single-use and time-limited

### 4. Sensitive Data Exposure (A02:2021)

**Red Flag:**
```python
# VULNERABLE
logger.debug(f"User login: {email}, password: {password}")
return {"error": str(exception)}  # May leak internals
```

**Checklist:**
- [ ] Passwords never logged
- [ ] API responses don't leak internal fields
- [ ] Error messages don't reveal system internals
- [ ] Secrets not hardcoded in source
- [ ] Sensitive data not in URL parameters

### 5. Broken Access Control (A01:2021)

**Red Flag:**
```python
# VULNERABLE - no ownership check
def get_document(document_id: str):
    return database.get_document(document_id)  # Who owns this?

# SAFE
def get_document(requesting_user: RequestingUser, document_id: str):
    doc = database.get_document(requesting_user["tenant_id"], document_id)
    if doc["owner_id"] != requesting_user["id"]:
        raise ForbiddenError("Not your document")
```

```python
# VULNERABLE - policy check only in router, not in service
@router.post("/profile")
def update_profile(request: Request, ...):
    if not settings.allow_users_edit_profile:  # Router-only check
        raise ForbiddenError(...)
    return service.update_profile(...)  # API route bypasses this

# SAFE - policy check in service layer
def update_profile(requesting_user, ...):
    if not _can_user_edit_profile(requesting_user):  # Service enforces
        raise ForbiddenError(...)
```

**Checklist:**
- [ ] All endpoints verify resource ownership
- [ ] IDOR prevention (can't access others' resources by changing IDs)
- [ ] Role checks prevent privilege escalation
- [ ] Admin functions properly restricted
- [ ] Policy checks enforced in **service layer**, not just routers
- [ ] CRUD lifecycle consistency (if create is super_admin-only, update/delete should be too)

### 6. Security Misconfiguration (A05:2021)

**Red Flag:**
```python
# VULNERABLE
app.add_middleware(CORSMiddleware, allow_origins=["*"])
response.set_cookie("session", token)  # Missing security flags

# SAFE
response.set_cookie("session", token, httponly=True, secure=True, samesite="lax")
```

**Checklist:**
- [ ] Debug mode disabled in production
- [ ] CORS properly restricted (not `*`)
- [ ] Cookie security flags set (HttpOnly, Secure, SameSite)
- [ ] Security headers configured

### 7. CSRF (A01:2021)

**Checklist:**
- [ ] State-changing operations require CSRF tokens
- [ ] Tokens validated server-side
- [ ] SameSite cookie attribute set
- [ ] API endpoints use non-cookie auth or CSRF

### 8. Insecure Deserialization (A08:2021)

**Red Flags:**
```python
# VULNERABLE
data = pickle.loads(request.body)
config = yaml.load(user_input)  # No SafeLoader
result = eval(user_expression)

# SAFE
config = yaml.safe_load(user_input)
data = json.loads(request.body)
```

**Checklist:**
- [ ] No `pickle.loads()` on untrusted data
- [ ] `yaml.load()` uses `Loader=SafeLoader`
- [ ] No `eval()` or `exec()` on user input
- [ ] JWT properly validated (signature, expiration, issuer)

### 9. Known Vulnerabilities (A06:2021)

Use `/deps` agent for dependency scanning.

### 10. Insufficient Logging (A09:2021)

**Checklist:**
- [ ] Auth events logged (login success/failure, logout, password reset)
- [ ] Authorization failures logged
- [ ] Logs don't contain sensitive data
- [ ] Log injection prevented (structured logging)

### 11. Unbounded Input (Resource Exhaustion)

**Red Flag:**
```python
# VULNERABLE - no length limit on schema
class UserInput(BaseModel):
    name: str
    description: str | None = None

# SAFE - explicit limits
class UserInput(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = Field(default=None, max_length=2000)
```

```python
# VULNERABLE - no length limit on form parameter
password: Annotated[str, Form()]

# SAFE - explicit limit
password: Annotated[str, Form(max_length=255)]
```

```python
# VULNERABLE - no bounds on numeric security parameter
grace_period_days: int = Query(default=7)

# SAFE - explicit bounds
grace_period_days: int = Query(default=7, ge=0, le=90)
```

**Checklist:**
- [ ] All Pydantic input schema `str` fields have `max_length`
- [ ] All `Form()` str parameters in route handlers have `max_length`
- [ ] Numeric parameters in security contexts have `ge`/`le` bounds
- [ ] Database TEXT columns have `CHECK (length(...) <= N)` or use `VARCHAR(N)`
- [ ] URL fields limited to 2048 characters
- [ ] XML/large content fields have a reasonable upper bound (e.g., 1MB)
- [ ] No unbounded TEXT columns accepting user input without validation
- [ ] Web form routes and API routes to the same service use equivalent validation

## Severity Guide

- **Critical**: RCE, full database access, authentication bypass
- **High**: Data breach potential, privilege escalation, IDOR
- **Medium**: XSS, CSRF on sensitive actions, information disclosure
- **Low**: Missing headers, minor misconfigurations, theoretical risks
