#!/usr/bin/env python3
import argh
from pathlib import Path
import sys
import sql


MIGRATIONS_DIR = Path("migrations")


def _ensure_table():
    sql.execute("""
        create table if not exists sql_migrations
        (
            name       text primary key,
            applied_at timestamptz not null default now()
        )
    """)


def _is_applied(name: str) -> bool:
    return bool(sql.fetchone("select 1 from sql_migrations where name=%s", (name,)))


def _run_migration(name: str, sql_text: str, dry_run: bool = False):
    if _is_applied(name):
        print(f"{name}: already applied")
        return
    print(f"Applying {name}...")
    if dry_run:
        print("dry-run, not executing SQL")
        return
    sql.execute(sql_text)
    sql.execute("insert into sql_migrations(name) values (%s)", (name,))
    print(f"{name}: done")


def _load_sql_files() -> list[Path]:
    if not MIGRATIONS_DIR.exists():
        print(f"migrations directory not found at: {MIGRATIONS_DIR.resolve()}", file=sys.stderr)
        return []
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def ls():
    """List migrations in ./migrations and their applied status."""
    _ensure_table()
    files = _load_sql_files()
    if not files:
        print("No migrations found.")
        return
    print("Migrations:")
    for f in files:
        stem = f.stem
        status = "Applied" if _is_applied(stem) else "Pending"
        print(f"- {stem} - {status}")


@argh.arg('--dry-run', default=False, help="show what would run without executing SQL")
def run(dry_run: bool = False):
    """Apply all pending migrations in alphanumeric order."""
    _ensure_table()
    files = _load_sql_files()
    if not files:
        print("No migrations found.")
        return
    print("Applying pending migrations...")
    for f in files:
        _run_migration(f.stem, f.read_text(), dry_run=dry_run)


if __name__ == "__main__":
    parser = argh.ArghParser()
    parser.add_commands([ls, run])
    parser.dispatch()
