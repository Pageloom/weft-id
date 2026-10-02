"""Create (if missing) and migrate the unit-test database.

`make test` runs the unit tests against their own database, ``appdb_test``,
next to the dev ``appdb`` in the dev Postgres container. The dev worker only
connects to ``appdb``, so its periodic sweeps (back-channel logout delivery,
session cleanup, ...) cannot take rows a test is about to assert on.

Run from the host with the dev stack up: ``poetry run python dev/test_db.py``
(``make test-db``). Idempotent: an existing database is only migrated.
"""

import os
import subprocess
import sys
from pathlib import Path

import psycopg

TEST_DB = os.environ.get("TEST_POSTGRES_DB", "appdb_test")
ROOT = Path(__file__).resolve().parent.parent

SUPERUSER = {
    "host": os.environ.get("POSTGRES_HOST", "localhost"),
    "port": os.environ.get("POSTGRES_PORT", "5432"),
    "user": "postgres",
    "password": os.environ.get("POSTGRES_SUPERUSER_PASSWORD", "postgres"),
}


def ensure_database() -> None:
    with psycopg.connect(dbname="postgres", autocommit=True, **SUPERUSER) as conn:
        exists = conn.execute("select 1 from pg_database where datname = %s", (TEST_DB,)).fetchone()
        if exists:
            return
        print(f"Creating database {TEST_DB} ...", flush=True)
        conn.execute(f'CREATE DATABASE "{TEST_DB}"')

    # The baseline schema configures the database it names ("appdb"); give
    # the test database the same settings.
    with psycopg.connect(dbname=TEST_DB, autocommit=True, **SUPERUSER) as conn:
        conn.execute(f'ALTER DATABASE "{TEST_DB}" SET timezone TO \'UTC\'')


def migrate() -> None:
    env = {
        **os.environ,
        "POSTGRES_HOST": SUPERUSER["host"],
        "POSTGRES_PORT": SUPERUSER["port"],
        "POSTGRES_USER": SUPERUSER["user"],
        "POSTGRES_PASSWORD": SUPERUSER["password"],
        "POSTGRES_DB": TEST_DB,
    }
    env.pop("APPUSER_PASSWORD", None)  # never re-key the shared appuser role from here
    subprocess.run(
        [sys.executable, str(ROOT / "db-init" / "migrate.py")],
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> None:
    ensure_database()
    migrate()
    # Owned by appowner like appdb, after the baseline ran (it creates the role).
    with psycopg.connect(dbname="postgres", autocommit=True, **SUPERUSER) as conn:
        conn.execute(f'ALTER DATABASE "{TEST_DB}" OWNER TO appowner')


if __name__ == "__main__":
    main()
