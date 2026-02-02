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

**Checklist:**
- [ ] Search templates for `| safe` usage without justification comment
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

**Checklist:**
- [ ] All endpoints verify resource ownership
- [ ] IDOR prevention (can't access others' resources by changing IDs)
- [ ] Role checks prevent privilege escalation
- [ ] Admin functions properly restricted

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

## Severity Guide

- **Critical**: RCE, full database access, authentication bypass
- **High**: Data breach potential, privilege escalation, IDOR
- **Medium**: XSS, CSRF on sensitive actions, information disclosure
- **Low**: Missing headers, minor misconfigurations, theoretical risks
