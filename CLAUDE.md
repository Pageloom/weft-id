# Project Instructions

## What This Project Is

Weft-ID is a multi-tenant identity federation platform that acts as middleware between applications and identity providers (Okta, Entra ID, Google Workspace, SAML/OIDC). Core capabilities:

- SAML 2.0 and OAuth2 identity provider integration
- SAML 2.0 Identity Provider for downstream service providers (SSO assertions, per-SP signing certificates)
- Multi-factor authentication (TOTP-based with backup codes)
- User lifecycle management with inactivation/reactivation workflows
- Comprehensive audit logging and activity tracking
- Tenant-isolated data with Row-Level Security (RLS)

## Before Starting Work

**Read `.claude/THOUGHT_ERRORS.md`** for common mistakes to avoid. Key gotchas:

- **Tests**: Use `poetry run python -m pytest` or `./test` (not `pytest` directly)
- **Code quality**: Run `make check` (lint, format, type check, compliance)
- **UUIDs**: Convert to string when comparing across boundaries
- **Background jobs**: Restart worker container, not app container
- **Mocking sessions**: Patch `starlette.requests.Request.session`, not client cookies

## Git Commits

- Keep them short and to the point
- The summary should be short (80 chars or less)
- The description should include a short definition of what problem was addressed
- The description should then explain, tersely, how it was done
- Do NOT include Claude attributions in commit messages

## Architecture Overview

This project follows a layered architecture:

```
Request → Router → Service → Database → PostgreSQL
```

- **Routers** (`app/routers/`): HTTP/template layer only. Never import database modules directly.
- **Services** (`app/services/`): Business logic and authorization. Receives `RequestingUser`, returns Pydantic schemas, raises `ServiceError` subclasses.
- **Database** (`app/database/`): SQL execution with tenant scoping. Returns dicts.

### Authentication vs Authorization

- **Authentication** (router layer): FastAPI dependencies in `app/dependencies.py` and `app/api_dependencies.py` identify the caller and return a user dict. They redirect unauthenticated users.
- **Authorization** (service layer): Functions in `app/services/auth.py` check role-based access. They receive a `RequestingUser` and raise `ForbiddenError` if the role is insufficient.

## Key Files

| File | Purpose |
|------|---------|
| `app/pages.py` | Authorization registry. All routes must be registered here |
| `app/constants/event_types.py` | Event type registry for audit logging |
| `app/schemas/common.py` | `RequestingUser` TypedDict and common schemas |
| `app/services/exceptions.py` | ServiceError subclasses (ForbiddenError, NotFoundError, ValidationError) |
| `app/services/event_log.py` | `log_event()` function for audit logging |
| `app/services/activity.py` | `track_activity()` for read operation tracking |
| `app/utils/crypto.py` | HKDF key derivation from `SECRET_KEY` (session, MFA, SAML, email) |
| `BACKLOG.md` | Product backlog (pending items) |
| `BACKLOG_ARCHIVE.md` | Completed backlog items with acceptance criteria |
| `ISSUES.md` | Active quality/security issues (goal: keep empty) |
| `ISSUES_ARCHIVE.md` | Resolved issues with fix details |
| `app/services/service_providers.py` | SP registration, SSO response building |
| `app/routers/saml_idp/` | SAML IdP admin, SSO, metadata (package) |
| `app/database/service_providers.py` | SP database queries |
| `app/database/sp_signing_certificates.py` | Per-SP signing certificate queries |
| `app/templates/icons/` | SVG icon files (19 Heroicons outline, viewable as images) |
| `static/js/utils.js` | Shared `WeftUtils` JS object (modals, sticky bars, clipboard, locale) |
| `static/js/cytoscape.min.js` | Cytoscape.js graph library (group graph views) |
| `app/version.py` | Runtime version via `importlib.metadata` (falls back to baked-in `VERSION` file) |
| `VERSIONING.md` | Semver policy: patch/minor/major definitions, identity-specific rules |
| `CHANGELOG.md` | Release changelog (Keep a Changelog format) |
| `Dockerfile` | Production multi-stage build (GHCR images, no dev deps) |
| `app/Dockerfile` | Dev build (used by `docker-compose.yml`) |
| `docker-compose.production.yml` | Self-hosting compose (Caddy + GHCR image, automatic HTTPS) |
| `Caddyfile` | Caddy reverse proxy config (on-demand TLS for tenant subdomains) |
| `.env.production.example` | Production environment template with generation instructions |
| `install.sh` | Self-hosting install script (downloads files, generates secrets, writes .env) |
| `.github/workflows/publish.yml` | GHCR publish workflow (triggers on `v*.*.*` tags) |
| `app/cli/provision_tenant.py` | CLI to provision a tenant and super admin (`python -m app.cli.provision_tenant`) |
| `app/dev/seed_dev.py` | Meridian Health dev seed script (canonical dev data fixture) |
| `mkdocs.yml` | Zensical documentation site configuration |
| `docs/` | Documentation site source (Markdown) |
| `site/` | Built documentation site (checked in, served at `/docs`) |
| `docs/decisions/` | Architectural Decision Records (ADRs) for foundational design choices |
| `.claude/THOUGHT_ERRORS.md` | Common mistakes to avoid |

## Directory Structure

```
app/
├── cli/              # CLI management commands (run via python -m app.cli.<command>)
├── routers/          # HTTP layer (imports services only)
│   ├── api/v1/       # RESTful API endpoints
│   ├── auth/         # Login, logout, onboarding (package)
│   ├── saml/         # SAML SP authentication (package)
│   ├── saml_idp/     # SAML IdP admin, SSO, metadata (package)
│   └── users/        # User management (package)
├── services/         # Business logic (imports database)
│   ├── users/        # User CRUD, profile, lifecycle (package)
│   ├── groups/       # Group CRUD, hierarchy, membership (package)
│   └── saml/         # SAML providers, certificates (package)
├── database/         # SQL execution (returns dicts)
│   ├── groups/       # Group queries (package)
│   ├── oauth2/       # OAuth2 queries (package)
│   ├── saml/         # SAML queries (package)
│   └── users/        # User queries (package)
├── schemas/          # Pydantic models
├── templates/        # Jinja2 templates
├── middleware/       # Request processing
├── jobs/             # Background task handlers
└── constants/        # Enums and constants
tests/                # Mirrors app/ structure
├── e2e/              # Playwright E2E tests (run via ./test-e2e)
db-init/              # Database schema baseline + migration runner
  schema.sql          # Complete baseline schema (applied on fresh DB)
  migrate.py          # Forward-only migration runner
  migrations/         # Incremental migration files (0001_name.sql)
scripts/              # Compliance and dependency checks
docs/                 # Documentation site (Zensical source)
  internal/           # Developer planning docs
  decisions/          # Architectural Decision Records (ADRs)
  getting-started/    # Getting started guide
  admin-guide/        # Administrator documentation
  user-guide/         # End-user documentation
  api/                # API documentation
  self-hosting/       # Self-hosting guide
site/                 # Built documentation site (served at /docs)
.claude/skills/       # Skill definitions (/pm, /dev, /test, etc.)
.claude/references/   # Detailed patterns and checklists for agents
```

### Package-Split Pattern

When a module grows large, it is split into a package directory with focused submodules:

- Public submodules are named by concern (e.g., `crud.py`, `hierarchy.py`, `membership.py`)
- Private helpers use an underscore prefix (e.g., `_converters.py`, `_validation.py`)
- `__init__.py` re-exports public functions for backwards compatibility
- When splitting a module into a package, mock targets in tests must be updated to reference the submodule (e.g., `routers.users.crud.some_func` instead of `routers.users.some_func`)

## Core Types

**RequestingUser** (TypedDict in `app/schemas/common.py`):
```python
{
    "id": str,           # User ID
    "tenant_id": str,    # Tenant ID for scoping
    "role": str,         # "super_admin" | "admin" | "user"
    "email": str,
    # ... additional fields
}
```

**ServiceError Subclasses** (in `app/services/exceptions.py`):
- `ForbiddenError` - Authorization failures (403)
- `NotFoundError` - Resource not found (404)
- `ValidationError` - Input validation failures (400)

## Service Function Pattern

```python
def do_something(
    requesting_user: RequestingUser,
    data: SomeSchema,
) -> ResultSchema:
    """Authorization: Requires admin role."""
    _require_admin(requesting_user)
    # ... business logic ...
    # ... database calls ...
    # ... event log ...
    return ResultSchema(...)
```

## Event Logging Pattern

**Writes must log events** (after successful mutation):
```python
from app.services.event_log import log_event

log_event(
    tenant_id=requesting_user["tenant_id"],
    actor_user_id=requesting_user["id"],
    event_type="user_created",  # Past tense, from event_types.py
    artifact_type="user",
    artifact_id=user_id,
    metadata={"role": user_data.role}  # Context for audit trail
)
```

**Reads must track activity** (at function start):
```python
from app.services.activity import track_activity

def get_users(requesting_user: RequestingUser) -> list[UserResponse]:
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    # ... rest of function
```

## Tenant Isolation

Database functions use Row-Level Security (RLS):
- All queries are scoped via `tenant_id` parameter
- Use `UNSCOPED` constant for intentional cross-tenant operations (system tasks only)
- Database layer functions: `fetchall(tenant_id, ...)`, `fetchone(tenant_id, ...)`, `execute(tenant_id, ...)`

## Group System Architecture

Groups organize users and support hierarchical relationships via a DAG (Directed Acyclic Graph) model.

### Data Model

| Table | Purpose |
|-------|---------|
| `groups` | Group definitions (name, description, type) |
| `group_memberships` | User-to-group membership |
| `group_relationships` | Direct parent-child edges |
| `group_lineage` | Closure table for all ancestor-descendant pairs |

### DAG Model

- Groups can have **multiple parents** (unlike a tree)
- Only true cycles are prevented (A cannot be both ancestor AND descendant of B)
- Example: Groups A and B can both be children of C, and A can become a child of B

### Closure Table Pattern

The `group_lineage` table pre-computes all ancestor-descendant relationships:

```
ancestor_id | descendant_id | depth
------------+---------------+------
group_a     | group_a       | 0      -- self-reference (every group has this)
group_a     | group_b       | 1      -- direct child
group_a     | group_c       | 2      -- grandchild (transitive)
```

**Benefits:**
- O(1) cycle detection: `SELECT 1 FROM group_lineage WHERE ancestor_id = child AND descendant_id = parent`
- O(1) ancestry queries: find all ancestors or descendants with a single query
- Depth tracking enables hierarchy visualization

**Maintenance:**
- On group creation: insert self-reference row `(group_id, group_id, 0)`
- On relationship creation: insert transitive paths atomically (all ancestors of parent become ancestors of all descendants of child)
- On relationship deletion: rebuild lineage for affected subtree

### Transactional Consistency

Relationship changes must update both `group_relationships` AND `group_lineage` atomically. Use the database `session()` context manager for transactions:

```python
with session(tenant_id=tenant_id) as cur:
    # 1. Insert/delete the direct relationship
    cur.execute(...)
    # 2. Update the lineage table
    cur.execute(...)
    # Transaction commits when context exits
```

### Group Types

- `weftid`: Manually managed groups (admin can add/remove members)
- `idp`: Identity Provider groups (synced from external IdP, read-only in WeftId)

## Frontend: Icons, JavaScript Utilities, and Graph Views

### Icons

All SVG icons are centralized in `app/templates/icons/` as pure, valid SVG files (viewable as images). Never paste inline SVGs into templates. Use the `icon()` global function (registered in `app/utils/templates.py`):

```jinja2
{{ icon("chevron-down", class="w-4 h-4 text-gray-400") }}
{{ icon("chevron-down", class="w-4 h-4", id="filter-chevron") }}
```

No import needed. `icon()` is a Jinja2 global available in all templates. It reads the SVG file and injects the provided HTML attributes (`class`, `id`, etc.) onto the `<svg>` element.

Available icons (all Heroicons outline): `arrow-path`, `arrow-right`, `arrows-pointing-in`, `arrows-pointing-out`, `arrows-up-down`, `check`, `check-circle`, `chevron-down`, `chevron-right`, `chevron-up`, `clipboard`, `cursor-arrow-rays`, `download`, `envelope`, `exclamation-circle`, `exclamation-triangle`, `information-circle`, `link`, `link-slash`, `pencil`, `server-stack`, `shield-check`, `squares-plus`, `user`, `user-group-plus`, `x-mark`.

To add a new icon: create `app/templates/icons/<name>.svg` as a valid SVG with `xmlns="http://www.w3.org/2000/svg"`. Use Heroicons outline paths with `viewBox="0 0 24 24"`. The `icon()` function handles attribute injection at render time.

### WeftUtils

Common UI patterns are consolidated in `static/js/utils.js` as the `WeftUtils` object. Before writing new JavaScript, check what's already there: confirmation modals, show/hide modals, clipboard copy, sticky action bars, locale/timezone detection. Inline event handlers (`onclick`, `onsubmit`) are blocked by CSP — use `WeftUtils` or `<script nonce="{{ csp_nonce }}">` blocks instead.

- `WeftUtils.apiFetch(url, options)` — drop-in `fetch()` wrapper for state-changing API calls. Automatically injects the `X-CSRF-Token` header (from the `<meta name="csrf-token">` tag) on POST/PUT/PATCH/DELETE requests and sets `credentials: 'same-origin'`. Always use this instead of bare `fetch()` for state-changing requests.
- `WeftUtils.listManager(config)` — universal list view manager. Handles localStorage persistence (page size + filter state), collapsible filter panel (toggle, apply, clear), page size selector, and multiselect with a sticky bulk action bar. See `.claude/references/list-view-patterns.md` for the full config shape and examples.

All JavaScript in this project targets **ES2020** (`const`/`let`, arrow functions, template literals, optional chaining — no `var`). See `.claude/references/js-patterns.md`. Server-side template values must be placed in a `<script type="application/json" id="page-data">` block and read via `JSON.parse(...)` — never embed `{{ }}` expressions directly in `<script>` bodies.

### Cytoscape.js (Group Graphs)

Group list and detail pages use Cytoscape.js (`static/js/cytoscape.min.js`) for interactive graph views. Key rule: **always initialize Cytoscape on a visible container.** If the graph is inside a hidden tab, defer initialization to `requestAnimationFrame` after the tab becomes visible. Initializing on a hidden container results in a zero-size layout with no error.

Graph layouts are persisted to the database via `PUT /api/v1/groups/graph/layout`.

## Versioning & Release

The canonical version lives in `pyproject.toml`. `app/version.py` exposes it at runtime via
`importlib.metadata`, falling back to a baked-in `VERSION` file in production images (where the
package isn't installed with `--no-root`). See `VERSIONING.md` for the full policy.

**Two Dockerfiles:**
- `app/Dockerfile` — dev build (all deps, dev entrypoint with `--reload`, used by `docker-compose.yml`)
- `Dockerfile` (root) — production multi-stage build (main deps only, no dev scripts, OCI labels)

Changes to the dev Dockerfile may need mirroring in the production one if they affect dependencies,
static assets, or the app directory structure.

**Self-hosting:** `docker-compose.production.yml` runs the GHCR image with Caddy for automatic HTTPS
(on-demand TLS, HTTP-01 challenge). Migrations run automatically before the app starts. See
`.env.production.example` for configuration. The migrate service connects as `postgres` (superuser);
the app connects as `appuser` (created by `schema.sql`) to preserve RLS enforcement. `install.sh`
automates first-time setup (downloads files, generates secrets, prompts for domain/SMTP, writes `.env`).
After install, provision the first tenant and super admin via CLI:
`docker compose exec app python -m app.cli.provision_tenant --subdomain <sub> --tenant-name <name> --email <email> --first-name <first> --last-name <last>`.
The super admin receives an invitation email and goes through the standard onboarding flow.

**Release flow:** bump version in `pyproject.toml`, tag `v1.2.3` on main, push the tag. The GHCR
workflow validates the tag matches `pyproject.toml`, then builds and pushes to `ghcr.io/pageloom/weft-id`.

## Background Jobs

Background jobs run in a separate worker container.
- Code location: `app/jobs/`
- Job registry: `app/jobs/registry.py`
- **Changes require worker restart**: `docker compose restart worker`

## Development Commands

### Python Development Tasks (Use Poetry)

**Run tests:**
```bash
./test                                                         # Run all tests (parallelized by default)
poetry run python -m pytest                                    # Full command
poetry run python -m pytest --cov=app --cov-report=term-missing  # With coverage report
make watch-tests                                               # Watch mode: auto-rerun only affected tests on file changes
./test --testmon                                               # Run only tests affected by recent changes (one-time)
```

Note: Tests run in parallel by default (`-n auto` configured in `pytest.ini`).

**Watch mode** (`make watch-tests`) uses `pytest-testmon` to intelligently run only tests affected by your code changes. On first run, it builds a coverage database (`.testmondata`). Subsequent runs only execute tests that cover the changed code, providing much faster feedback than running the full suite.

**Code quality (lint, format, type check, compliance):**
```bash
make check                                  # Run all checks (CI-equivalent)
make fix                                    # Auto-fix lint/format, then check types and compliance
```

**Dependency security scanning:**
```bash
python scripts/deps_check.py                # Scan dependencies
python scripts/deps_check.py --include-dev  # Include dev deps
```

**E2E tests (Playwright):**
```bash
./test-e2e                          # Run all E2E tests (requires Docker services running)
./test-e2e --headed --slowmo=500    # Debug in visible browser
./test-e2e -k test_sp_initiated     # Run specific test
./test-e2e --tb=long                # Verbose tracebacks
```

E2E tests live in `tests/e2e/` and are **excluded** from `./test` (via `--ignore=tests/e2e` in `pytest.ini`). They run sequentially (`-n 0`) and require Docker services plus MailDev to be running. Tests are skipped automatically if MailDev is not reachable.

**Combined coverage (unit + E2E):**
```bash
./test-coverage-all                 # Merged coverage from both test suites
./test-coverage-all --html          # Also generate htmlcov/ report
```

Runs unit tests and E2E tests separately with coverage collection, then uses `coverage combine` to merge data files into a single report. Shows true overall coverage including SAML SSO/SLO paths that only E2E tests exercise.

### Docker Infrastructure (Use Make)

**Service management:**
```bash
make up          # Build and start all services
make down        # Stop and remove containers
make status      # Show service status
make db-reset    # Wipe DB volume
make restart-app # Restart specific service
```

**Logs and debugging:**
```bash
make logs        # Tail all logs
make logs-app    # Tail specific service logs
make sh-app      # Open shell in service container
```

**Frontend/CSS build:**
```bash
make build-css   # Build Tailwind CSS (run after modifying templates)
make watch-css   # Watch templates and auto-rebuild CSS (recommended for active development)
```

**Documentation site:**
```bash
make docs        # Build docs from docs/ into site/ (must be committed)
```

The documentation site is built from Markdown sources in `docs/` using Zensical (reads `mkdocs.yml` for configuration). The built output in `site/` is checked into git and served by the app at `/docs`. To update the docs: edit files in `docs/`, run `make docs`, and commit both `docs/` and `site/`.

**Quick reference:**
```bash
make help        # Show all available targets
```

**Database migrations:**

Migrations run automatically on `make up` in dev (via the `migrate` one-shot service).

```bash
make migrate         # Apply pending migrations on running dev DB
make db-init         # Wipe DB volume and reinitialize (baseline + migrations)
```

**Creating a new migration:**
1. Create a `.sql` file in `db-init/migrations/` with 4-digit prefix: `0001_description.sql`
2. Write pure SQL (no `BEGIN/COMMIT`, no psql directives like `\set`)
3. Use `SET LOCAL ROLE appowner;` at the top for DDL ownership
4. The runner wraps each migration in its own transaction

**Checking migration status:**
```bash
docker compose exec -T db psql -U postgres -d appdb \
  -c "SELECT version, status, started_at, completed_at FROM schema_migration_log ORDER BY id"
```

**On failure:** The runner logs the error in `schema_migration_log`, rolls back the transaction, and exits non-zero. Fix the migration file and rerun `make migrate` to retry.

### Frontend Development Workflow

**Tailwind CSS is built locally** from `static/css/input.css` → `static/css/output.css`

The build process scans all templates (`app/templates/**/*.html`) and generates CSS containing only the Tailwind utility classes actually used in your templates.

**When adding new Tailwind classes to templates:**

**Option 1: Manual rebuild** (when needed)
```bash
make build-css
```
Run this after you've added new Tailwind classes to any template file. The generated CSS will be updated with the new classes.

**Option 2: Watch mode** (recommended for active development)
```bash
make watch-css
```
Leave this running in a separate terminal while working on templates. It automatically detects changes to HTML files and rebuilds the CSS. Press Ctrl+C to stop watching.

**In Docker:**
The CSS is built during the Docker image build process, so running `make up` will always rebuild the CSS from scratch.

### Development Workflow

**Starting a development session:**
1. Start Docker services: `make dev` (builds, starts, shows status)
2. (Optional) Start watch modes in separate terminals:
   - CSS: `make watch-css` - auto-rebuild CSS on template changes
   - Tests: `make watch-tests` - intelligently rerun only affected tests on code changes
3. Work on code/templates normally
4. Watch modes provide immediate feedback if running

**Note on test watch mode**: The first run builds a coverage database. After that, only tests affected by your changes will run, making iterations much faster (e.g., changing one function might run 5 tests instead of 500).

**Before committing code:**
1. Run code quality checks: `make fix`
2. Run tests: `make test`
3. If you modified templates and didn't use watch mode: `make build-css`

All checks must pass before committing.

## Best Practices

1. **All writes go through the service layer** - routers never call database modules directly
2. **Every service write must emit an event log** - "if there is a write, there is a log"
3. **Read service functions must track activity** - call `track_activity(tenant_id, user_id)` at the start of read-only service functions
4. **Authorization via `app/pages.py`** - single source of truth for page access and navigation
5. **New pages must be registered in `app/pages.py`** - each route checks access via this file
6. **Migrations** go in `db-init/migrations/` with 4-digit numbering (e.g. `0001_description.sql`). Pure SQL, no `BEGIN/COMMIT`, use `SET LOCAL ROLE appowner` for DDL
7. **Run formatting and linting** before committing code
8. **API-first methodology** - any functionality available in the web client must also be exposed via API endpoints under `/api/v1/`. API endpoint docstrings must document all accepted fields/parameters (not a subset).
9. **Backlog management** - after completing a BACKLOG.md item, move it to BACKLOG_ARCHIVE.md with status marked as Complete
10. **All string fields must have `max_length`** - every `str` field in Pydantic input schemas (Create, Update, Import) must specify `max_length`. Use these standard limits: names/titles 255, descriptions 2000, URLs 2048, enum-like fields 50, subdomains 63, domains 253. Database columns should have matching `CHECK` constraints or `VARCHAR(N)` types.
11. **Use watch mode during development** - run `make watch-tests` in a separate terminal to get immediate feedback on code changes. It intelligently reruns only affected tests, providing fast iteration cycles (seconds instead of minutes).
12. **State-changing fetch() calls to API endpoints must use `WeftUtils.apiFetch()`** - bare `fetch()` with `credentials: 'same-origin'` on a non-GET endpoint is a CSRF vulnerability. Bearer-token clients are unaffected.

## Testing Requirements

- **New code must have comprehensive test coverage** - aim for ~100% on new code
- **Test both layers**: unit tests for service functions, integration tests for routes/API endpoints
- **Cover happy paths and key edge cases** - don't just test the golden path
- **All existing tests must pass** - never break existing functionality
- Tests live in `tests/` mirroring the app structure
- **E2E tests** live in `tests/e2e/` and run separately via `./test-e2e`. They cover SAML SSO flows (SP- and IdP-initiated), SLO, MFA (email and TOTP), group-based SP access, and login using Playwright. They are excluded from `./test`.
- **Test environment**: Tests set `IS_DEV=true` (in `tests/conftest.py`) to bypass production validation

## Agent Workflow

- Use `/pm` to add items to the product backlog
- Use `/dev` to implement items from the backlog (checks ISSUES.md first)
- Use `/test` to review quality and push coverage intelligently
- Use `/compliance` to verify architectural principles are followed
- Use `/security` to scan for OWASP Top 10 and other security vulnerabilities
- Use `/deps` to audit third-party dependencies for known CVEs and vulnerabilities
- Use `/refactor` to analyze codebase for refactoring opportunities and technical debt
- Use `/changelog` to draft changelog entries from git history before tagging a release
- Use `/tech-writer` to review app copy for clarity and maintain the documentation site

## Issue Tracking

- Quality issues found by `/test` are logged in `ISSUES.md`
- Architectural violations found by `/compliance` are logged in `ISSUES.md`
- Security vulnerabilities found by `/security` are logged in `ISSUES.md`
- Dependency vulnerabilities found by `/deps` are logged in `ISSUES.md`
- Refactoring opportunities found by `/refactor` are logged in `ISSUES.md`
- Copy inconsistencies found by `/tech-writer` are logged in `ISSUES.md`
- `/dev` checks ISSUES.md first before BACKLOG.md (bugs before features)
- **When resolved:** Move issues from `ISSUES.md` to `ISSUES_ARCHIVE.md` (don't keep resolved items in ISSUES.md)
- Goal: keep `ISSUES.md` empty
