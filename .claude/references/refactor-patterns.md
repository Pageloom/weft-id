# Refactoring Patterns Reference

This document contains detailed code smell patterns and fix examples for the `/refactor` agent.

## Primary Goal: Claude Traversability

Code structure directly impacts Claude's effectiveness. Prioritize issues that hurt traversability:

| Factor | Target | Why It Matters |
|--------|--------|----------------|
| File size | <500 lines, <300 preferred | Large files may not fit in context |
| Module boundaries | Single responsibility per file | One file = one concept |
| Consistent patterns | Same pattern everywhere | No re-learning per file |
| Self-documenting structure | Names match contents | Navigate without exploration |

## Code Smell Patterns

### File Structure

**God Module:**
```
app/services/saml.py (2600+ lines)
  - SAML request building
  - SAML response parsing
  - User provisioning
  - Group syncing
  - Session management
# Should be split into focused modules
```

**Scattered Concept:**
```
# To understand "user creation" you must read:
  - app/routers/users.py
  - app/services/users.py
  - app/database/users.py
  - app/schemas/users.py
  - app/services/email.py
  - app/jobs/welcome_email.py
```

### Code Duplication

**Validation Duplication:**
```python
# Found in multiple places - extract to shared validator
if not data.email or "@" not in data.email:
    raise ValidationError("Invalid email")
```

### Complex Functions

**God Function:**
```python
def process_user_request(request):
    # Validate input (20 lines)
    # Authenticate user (15 lines)
    # Authorize action (10 lines)
    # Perform business logic (30 lines)
    # Send notifications (15 lines)
    # Log audit trail (10 lines)

# Refactor to:
def process_user_request(request):
    validated = validate_request(request)
    user = authenticate(request)
    authorize(user, validated.action)
    result = execute_business_logic(validated)
    notify_stakeholders(result)
    log_audit(user, validated, result)
```

### Inconsistent Patterns

```python
# Inconsistent naming
def get_user(user_id): ...      # "get"
def fetch_groups(): ...          # "fetch"
def retrieve_permissions(): ...  # "retrieve"
# Standardize on one verb
```

### Tight Coupling

```python
# WRONG - hardcoded to email
def send_notification(user):
    sender = EmailSender()
    sender.send(user.email, message)

# BETTER - accept abstract notifier
def send_notification(user, notifier: Notifier):
    notifier.send(user, message)
```

## Quality of Test Code

**Nested Patch Pyramids:**
```python
# BAD
with patch("module.a") as mock_a:
    with patch("module.b") as mock_b:
        with patch("module.c") as mock_c:
            # test buried deep

# GOOD - use mocker fixture
def test_something(mocker):
    mock_a = mocker.patch("module.a")
    mock_b = mocker.patch("module.b")
    mock_c = mocker.patch("module.c")
    # test at top level
```

**Duplicated Setup:**
```python
# Extract to conftest.py fixture
@pytest.fixture
def authenticated_client(test_user):
    app.dependency_overrides[get_current_user] = lambda: test_user
    yield TestClient(app)
    app.dependency_overrides.clear()
```

## Refactoring Categories Quick Reference

| Category | Smell | Typical Fix |
|----------|-------|-------------|
| File Structure | God module (>500 lines) | Split into sub-modules |
| File Structure | Scattered concept | Consolidate related code |
| Duplication | Same code in 2+ places | Extract function |
| Complexity | Long method (>50 lines) | Extract method |
| Complexity | Deep nesting (>3 levels) | Guard clauses |
| Inconsistency | Mixed patterns | Standardize |
| Dead Code | Unused code | Delete it |
| Abstraction | God class | Extract class |
| Coupling | Hardcoded deps | Dependency injection |
| Test Code | Nested patches | Use `mocker.patch()` |
| Test Code | Duplicated setup | Extract to fixtures |
| Test Code | Missing docstrings | Add docstrings |
| Test Code | Repeated structures | Use `@pytest.mark.parametrize` |

## Thresholds

- **Files >500 lines**: Flag for splitting
- **Functions >100 lines**: Hard to understand
- **Functions >50 lines**: Consider refactoring
- **>3 imports from same module**: Check module boundaries
- **Nesting >3 levels**: Consider guard clauses
