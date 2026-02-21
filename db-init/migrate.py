#!/usr/bin/env python3
"""Forward-only database migration runner.

Three-state detection:
  1. schema_migration_log exists        -> check for pending migrations
  2. schema_migration_log AND tenants missing -> fresh DB, apply schema.sql
  3. schema_migration_log missing, tenants exists -> pre-existing DB, create
     only the log table with baseline record, then check for pending migrations

Usage:
  python migrate.py              # auto-detect and apply
  POSTGRES_HOST=db python migrate.py
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path

import psycopg

DB_INIT = Path(__file__).resolve().parent
SCHEMA_SQL = DB_INIT / "schema.sql"
MIGRATIONS_DIR = DB_INIT / "migrations"


def connect() -> psycopg.Connection:
    user = os.environ.get("POSTGRES_USER", "postgres")
    password = os.environ.get("POSTGRES_PASSWORD", "postgres")
    host = os.environ.get("POSTGRES_HOST", "db")
    port = os.environ.get("POSTGRES_PORT", "5432")
    dbname = os.environ.get("POSTGRES_DB", "appdb")
    conninfo = f"host={host} port={port} dbname={dbname} user={user} password={password}"
    return psycopg.connect(conninfo, autocommit=True)


def table_exists(conn: psycopg.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = %s",
        (table,),
    ).fetchone()
    return row is not None


def applied_versions(conn: psycopg.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT version FROM schema_migration_log WHERE status = 'success'"
    ).fetchall()
    return {r[0] for r in rows}


def failed_versions(conn: psycopg.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT DISTINCT version FROM schema_migration_log WHERE status = 'failed'"
    ).fetchall()
    return {r[0] for r in rows}


def clean_sql(raw: str) -> str:
    """Strip psql directives (lines starting with \\) from SQL."""
    lines = raw.splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("\\"))


def apply_sql(conn: psycopg.Connection, sql: str, label: str) -> None:
    """Execute SQL inside an explicit transaction."""
    cleaned = clean_sql(sql)
    print(f"  Applying {label} ...", flush=True)
    conn.execute("BEGIN")
    try:
        conn.execute(cleaned)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    print(f"  {label} applied successfully.", flush=True)


def apply_baseline(conn: psycopg.Connection) -> None:
    """Apply schema.sql to a fresh database."""
    print("Fresh database detected. Applying baseline schema ...", flush=True)
    sql = SCHEMA_SQL.read_text()
    apply_sql(conn, sql, "baseline schema")


def bootstrap_log_table(conn: psycopg.Connection) -> None:
    """Create schema_migration_log on a pre-existing DB and record baseline."""
    print(
        "Pre-existing database detected. Creating migration log ...",
        flush=True,
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migration_log (
            id              SERIAL PRIMARY KEY,
            version         TEXT NOT NULL,
            status          TEXT NOT NULL CHECK (status IN ('success', 'failed')),
            started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            completed_at    TIMESTAMPTZ,
            error_message   TEXT,
            error_traceback TEXT
        )
    """)
    conn.execute(
        "INSERT INTO schema_migration_log (version, status, completed_at) "
        "VALUES ('baseline', 'success', now())"
    )
    print("  Migration log created with baseline record.", flush=True)


def pending_migrations(already_applied: set[str]) -> list[Path]:
    """Return migration files not yet successfully applied, sorted."""
    if not MIGRATIONS_DIR.is_dir():
        return []
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    pending = []
    for f in files:
        version = f.stem  # e.g. "0001_add_column"
        if version not in already_applied:
            pending.append(f)
    return pending


def run_migration(conn: psycopg.Connection, path: Path) -> None:
    """Apply a single migration file with logging."""
    version = path.stem
    sql = path.read_text()

    # Insert optimistic failure record
    conn.execute(
        "INSERT INTO schema_migration_log (version, status) VALUES (%s, 'failed')",
        (version,),
    )

    try:
        apply_sql(conn, sql, version)
        # Mark success
        conn.execute(
            "UPDATE schema_migration_log "
            "SET status = 'success', completed_at = now() "
            "WHERE version = %s AND status = 'failed' AND completed_at IS NULL",
            (version,),
        )
    except Exception as exc:
        tb = traceback.format_exc()
        conn.execute(
            "UPDATE schema_migration_log "
            "SET error_message = %s, error_traceback = %s "
            "WHERE version = %s AND status = 'failed' AND completed_at IS NULL",
            (str(exc), tb, version),
        )
        print(f"  FAILED: {version}", file=sys.stderr, flush=True)
        print(f"  Error: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)


def main() -> None:
    conn = connect()

    has_log = table_exists(conn, "schema_migration_log")
    has_tenants = table_exists(conn, "tenants")

    if not has_log and not has_tenants:
        # State 2: fresh DB
        apply_baseline(conn)
    elif not has_log and has_tenants:
        # State 3: pre-existing DB without migration log
        bootstrap_log_table(conn)

    # State 1 (or after bootstrap): check for pending migrations
    already = applied_versions(conn)
    migrations = pending_migrations(already)

    if not migrations:
        print("No pending migrations.", flush=True)
    else:
        print(f"Found {len(migrations)} pending migration(s).", flush=True)
        for m in migrations:
            run_migration(conn, m)

    conn.close()
    print("Done.", flush=True)


if __name__ == "__main__":
    main()
