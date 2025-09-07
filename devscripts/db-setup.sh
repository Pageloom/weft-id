#!/bin/sh
# =============================================================================
# db-setup.sh — Apply SQL migrations in dev
#
# Purpose
#   Runs all SQL files in /sql/*.sql exactly once, in filename order.
#   Each migration is executed as the appowner so that new tables/sequences
#   are owned correctly; the migration is then recorded in
#   sql_migrations as the migrator user.
#
# How it’s invoked
#   Run inside a one-shot Compose service
#
# Preconditions
#   - Bootstrap init has already created roles: appowner (NOLOGIN), migrator
#     (LOGIN, GRANTED appowner), and appuser, and the target DB/schema exist.
#   - migrator can `SET ROLE appowner`.
#
# Behavior & guarantees
#   - Idempotent: keeps a ledger table (sql_migrations) and skips already-run files.
#   - Ordering: files run in lexicographic order
#   - Ownership: DDL runs as appowner (`SET ROLE appowner`), then role is reset
#     before inserting the ledger row (so INSERT runs as migrator and succeeds).
#   - Errors: `set -euo pipefail` + `ON_ERROR_STOP` — aborts on first failure.
# =============================================================================
set -euo pipefail

# 1) ensure tracking table exists
psql -v ON_ERROR_STOP=1 <<'SQL'
create table if not exists sql_migrations(
  filename   text primary key,
  applied_at timestamptz default now()
);
SQL

# 2) collect migration files; exit if none
files="$(ls -1 /sql/*.sql 2>/dev/null | sort || true)"
[ -n "$files" ] || { echo "no migrations found"; exit 0; }

# 3) apply each migration once, as appowner, then record it
for f in $files; do
  bn="$(basename "$f")"
  if psql -At -v ON_ERROR_STOP=1 -c "select 1 from sql_migrations where filename='${bn}'" | grep -q 1; then
    echo "skip  $bn"
  else
    echo "apply $bn"
    psql -v ON_ERROR_STOP=1 <<SQL
SET ROLE appowner;
\i '$f'
RESET ROLE;
INSERT INTO sql_migrations(filename) VALUES ('${bn}');
SQL
  fi
done
