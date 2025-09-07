#!/bin/sh
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
