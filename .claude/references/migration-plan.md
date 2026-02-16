# Plan: Baseline Schema + Forward-Only Migration System

## Context

The current migration setup (`db-init/` with 32 sequential SQL files) runs only once, on the
first `docker-compose up` when PostgreSQL initializes its data directory. After that, applying
a new migration requires a manual `docker compose exec -T db psql ...` command, and resetting
the database means wiping the entire volume and replaying all 32 files from scratch.

This plan replaces that with three things:
1. A single **baseline schema** that sets up a complete database from zero at any time
2. A lightweight **forward-only migration runner** (Python + psycopg) with a log table
3. **Dev-only auto-migration** via a compose override, plus `make migrate` for all environments

## Key Design Decisions

1. **Dev-only auto-migration.** The `migrate` one-shot service lives in `docker-compose.yml`
   (the dev compose file). It is not added to `docker-compose.onprem.yml`. Production never auto-migrates.

2. **On-demand utility.** `make migrate` is the standard way to apply migrations in all
   environments. It wraps `docker compose run --rm migrate`.

3. **Migration log with success/failure tracking.** A `schema_migration_log` table records
   every migration attempt. Successful migrations cannot be rerun. Failed migrations can be
   retried. Full error details (Postgres error + Python traceback) are captured for diagnostics.

## What Changes

### Files Created
- `db-init/schema.sql` -- complete baseline schema (consolidated from 32 migrations)
- `db-init/migrations/.gitkeep` -- directory for future incremental migrations
- `db-init/migrate.py` -- forward-only migration runner (~120 lines)

### Files Modified
- `docker-compose.yml` -- replace `initdb.d` mount with `migrate` one-shot service
- `docker-compose.onprem.yml` -- remove `initdb.d` mount (prod uses `make migrate` on demand)
- `Makefile` -- update `db-reset`/`db-init`, add `migrate` target
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
-- 10. SCHEMA_MIGRATION_LOG (log table)
```

**The `schema_migration_log` table:**

```sql
CREATE TABLE IF NOT EXISTS schema_migration_log (
    id              SERIAL PRIMARY KEY,
    version         TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('success', 'failed')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    error_traceback TEXT
);
-- No RLS, no tenant_id -- this is a system table.
-- Owned by postgres (not appowner) since it's infrastructure.
```

When the baseline is applied, it records itself:

```sql
INSERT INTO schema_migration_log (version, status, completed_at)
VALUES ('baseline', 'success', now());
```

**No psql directives.** The file is pure SQL (no `\set`, `\connect`, etc.) so it works
with both psycopg and `psql -f`.

**Role creation uses IF NOT EXISTS guards** (via `DO $$ ... END $$` blocks) so the baseline
is safe to run even if roles already exist.

---

## Step 2: Write `db-init/migrate.py`

A ~120 line Python script. No framework, no dependencies beyond psycopg (already in stack).

**Behavior:**

1. Connect to database (via `DATABASE_URL` env var, defaults to local dev)
2. Check if `schema_migration_log` table exists
3. **If no:** Fresh database. Run `schema.sql`, which creates everything including
   `schema_migration_log` with the `baseline` success record
4. **If yes:** Existing database. Query versions with `status = 'success'`, find pending
   migration files in `db-init/migrations/`, apply them in lexicographic order
5. Each migration runs in its own transaction:
   - Record `started_at` with status `failed` (optimistic failure record)
   - Execute the SQL
   - On success: update row to `status = 'success'`, set `completed_at`
   - On failure: update row with `error_message` and `error_traceback`, exit non-zero
6. A migration is skipped if it has any row with `status = 'success'`
7. A migration is eligible for rerun if it only has `status = 'failed'` rows

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

## Step 3: Update `docker-compose.yml` (dev)

**Remove** the `initdb.d` volume mount from the `db` service:

```yaml
# REMOVE this line:
- ./db-init:/docker-entrypoint-initdb.d:ro
```

**Add** the `migrate` one-shot service:

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

---

## Step 4: Update `docker-compose.onprem.yml` (prod)

**Remove** the `initdb.d` volume mount from the `db` service:

```yaml
# REMOVE this line:
- ./db-init:/docker-entrypoint-initdb.d:ro
```

No `migrate` service in the prod file. Migrations are run on demand via `make migrate`.

---

## Step 5: Update Makefile

```makefile
db-reset: ## Wipe DB volume to force full reinit
	$(COMPOSE) down -v

db-init: db-reset up ## Wipe DB and restart (runs baseline + migrations)

migrate: ## Run pending migrations on running DB
	$(COMPOSE) run --rm migrate
```

`make up` already uses `docker-compose.yml` which now includes the `migrate` service,
so auto-migration happens transparently in dev. The `migrate` target lets developers
manually run pending migrations without restarting everything.

---

## Step 6: Delete Old Migration Files

Remove all 32 files (`00000_bootstrap.sql` through `00031_sp_group_assignments.sql`) and
`README.md` from `db-init/`. Git history preserves them.

---

## Step 7: Update CLAUDE.md

Update the migration instructions section to reflect the new workflow:
- How to create a new migration (4-digit numbered `.sql` in `db-init/migrations/`)
- How to apply migrations (`make migrate` or automatic on `make up` in dev)
- How to reset the database (`make db-init`)
- Migration file conventions (pure SQL, 4-digit numbering, `SET LOCAL ROLE appowner`)
- Migration log: how to check status, what happens on failure, how to retry

---

## Verification

1. **Fresh database setup:**
   - `make db-init` (wipes volume, starts containers, migrate service applies baseline)
   - App starts, dev users are seeded, everything works
   - `schema_migration_log` table contains `baseline` success record

2. **Incremental migration:**
   - Create a test migration in `db-init/migrations/0001_test.sql` with a trivial change
   - `make migrate` applies it
   - `schema_migration_log` shows `baseline` (success) and `0001_test` (success)
   - Run `make migrate` again: "No pending migrations" (idempotent)

3. **Failed migration and retry:**
   - Create a migration with intentional SQL error
   - `make migrate` fails, logs error with full details in `schema_migration_log`
   - Fix the migration file
   - `make migrate` retries it successfully
   - Log shows both the failed attempt and the successful retry

4. **Schema equivalence:**
   - Compare `pg_dump --schema-only` from the baseline-initialized DB against the original
   - Verify tables, indexes, constraints, RLS policies, grants all match

5. **Tests still pass:** `./test`
