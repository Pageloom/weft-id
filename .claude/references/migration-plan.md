# Plan: Baseline Schema + Forward-Only Migration System

## Context

The current migration setup (`db-init/` with 32 sequential SQL files) runs only once, on the
first `docker-compose up` when PostgreSQL initializes its data directory. After that, applying
a new migration requires a manual `docker compose exec -T db psql ...` command, and resetting
the database means wiping the entire volume and replaying all 32 files from scratch.

This plan replaces that with three things:
1. A single **baseline schema** that sets up a complete database from zero at any time
2. A lightweight **forward-only migration runner** (Python + psycopg) with a changelog table
3. **Auto-migration on container startup** so developers never forget to apply changes

## What Changes

### Files Created
- `db-init/schema.sql` -- complete baseline schema (consolidated from 32 migrations)
- `db-init/migrations/.gitkeep` -- directory for future incremental migrations
- `db-init/migrate.py` -- forward-only migration runner (~100 lines)

### Files Modified
- `docker-compose.yml` -- add `migrate` service, remove `initdb.d` mount
- `Makefile` -- update `db-reset`, `db-init`, add `migrate` target
- `CLAUDE.md` -- update migration instructions

### Files Deleted
- `db-init/00000_bootstrap.sql` through `db-init/00031_sp_group_assignments.sql` (32 files)
- `db-init/README.md`

---

## Step 1: Generate the Baseline Schema

**Approach:** Use `pg_dump --schema-only` from the running dev database to capture the exact
current state, then restructure into a clean, readable file with logical sections.

```bash
docker compose exec -T db pg_dump -U postgres --schema-only --no-comments appdb > /tmp/raw_schema.sql
```

Then reorganize into `db-init/schema.sql` with this structure:

```
-- 1. ROLES (appowner, migrator, appuser)
-- 2. DATABASE & SCHEMA OWNERSHIP
-- 3. DEFAULT PRIVILEGES
-- 4. EXTENSIONS (pgcrypto, citext)
-- 5. TYPES (user_role enum, etc.)
-- 6. TABLES (in dependency order)
-- 7. INDEXES
-- 8. ROW LEVEL SECURITY (policies)
-- 9. GRANTS (explicit DML grants to appuser)
-- 10. SCHEMA_MIGRATIONS (changelog table)
```

**The `schema_migrations` table:**

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version  TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- No RLS, no tenant_id -- this is a system table.
-- Owned by postgres (not appowner) since it's infrastructure.
```

When the baseline is applied, it records itself:

```sql
INSERT INTO schema_migrations (version) VALUES ('baseline');
```

**No psql directives.** The file is pure SQL (no `\set`, `\connect`, etc.) so it works
with both psycopg and `psql -f`.

**Role creation uses IF NOT EXISTS guards** (via `DO $$ ... END $$` blocks) so the baseline
is safe to run even if roles already exist.

---

## Step 2: Write `db-init/migrate.py`

A ~100 line Python script. No framework, no dependencies beyond psycopg (already in stack).

**Behavior:**

1. Connect to database (via `DATABASE_URL` env var, defaults to local dev)
2. Check if `schema_migrations` table exists
3. **If no:** Fresh database. Run `schema.sql`, which creates everything including
   `schema_migrations` with the `baseline` record
4. **If yes:** Existing database. Query applied versions, find pending migration files
   in `db-init/migrations/`, apply them in lexicographic order
5. Each migration runs in its own transaction. On success, record in `schema_migrations`.
   On failure, roll back that migration and exit with error.

**psql directive handling:** Strip lines starting with `\` before executing. This lets
migration authors optionally include `\set ON_ERROR_STOP on` for manual psql use without
breaking the Python runner.

**Key details:**
- Connects as `postgres` superuser (same as current setup)
- Each migration file can use `SET LOCAL ROLE appowner` for DDL ownership
- Migrations are `.sql` files in `db-init/migrations/`, sorted lexicographically
- Uses 4-digit numbering: `0001_description.sql`, `0002_description.sql`
- Exit code 0 on success, 1 on failure (for docker-compose health)

---

## Step 3: Update `docker-compose.yml`

**Remove** the `initdb.d` volume mount from the `db` service:

```yaml
# REMOVE this line:
- ./db-init:/docker-entrypoint-initdb.d:ro
```

**Add** a `migrate` one-shot service:

```yaml
migrate:
  image: app:dev-latest
  container_name: dev_migrate
  entrypoint: []
  command: ["python", "/db-init/migrate.py"]
  working_dir: /app
  env_file: .env
  volumes:
    - ./db-init:/db-init:ro
  depends_on:
    db:
      condition: service_healthy
  networks: [devnet]
```

**Update** `app` and `worker` to depend on migrate:

```yaml
app:
  depends_on:
    migrate:
      condition: service_completed_successfully

worker:
  depends_on:
    migrate:
      condition: service_completed_successfully
```

The migrate service uses the same app image (has psycopg), mounts `db-init/` read-only,
runs the migration script, and exits. App and worker wait for it to complete.

---

## Step 4: Update Makefile

```makefile
db-reset: ## Wipe DB volume to force full reinit
	$(COMPOSE) down -v

db-init: db-reset up ## Wipe DB and restart (runs baseline + migrations)

migrate: ## Run pending migrations on running DB
	$(COMPOSE) run --rm migrate
```

The `db-init` target keeps its current behavior (wipe + restart, which now triggers
the migrate service automatically). The new `migrate` target lets developers manually
run pending migrations without restarting everything.

---

## Step 5: Delete Old Migration Files

Remove all 32 files (`00000_bootstrap.sql` through `00031_sp_group_assignments.sql`) and
`README.md` from `db-init/`. Git history preserves them.

---

## Step 6: Update CLAUDE.md

Update the migration instructions section to reflect the new workflow:
- How to create a new migration
- How to apply migrations (`make migrate` or automatic on `make up`)
- How to reset the database (`make db-init`)
- Migration file conventions (pure SQL, 4-digit numbering, `SET LOCAL ROLE appowner`)

---

## Verification

1. **Fresh database setup:**
   - `make db-init` (wipes volume, starts containers, migrate service applies baseline)
   - App starts, dev users are seeded, everything works
   - `schema_migrations` table contains `baseline` record

2. **Incremental migration:**
   - Create a test migration in `db-init/migrations/0001_test.sql` with a trivial change
   - `make migrate` applies it
   - `schema_migrations` table shows both `baseline` and `0001_test`
   - Run `make migrate` again: "No pending migrations" (idempotent)

3. **Schema equivalence:**
   - Compare `pg_dump --schema-only` from the baseline-initialized DB against the original
   - Verify tables, indexes, constraints, RLS policies, grants all match

4. **Tests still pass:** `./test`

---

## Design Decisions

1. **Runner language:** Python + psycopg (recommended). Reuses existing dependency, ~80-100
   lines, robust error handling and transaction support. Shell + psql was rejected as more
   fragile.

2. **Auto-migrate on startup:** Yes (recommended). A one-shot `migrate` service in
   docker-compose runs before the app starts. Zero friction for developers.

3. **Old db-init files:** Delete them. Git history preserves them. Clean slate in the repo.
