"""Tests for the migration runner's role password sync (db-init/migrate.py).

Self-hosted installs set APPUSER_PASSWORD, so the runner changes appuser's
password on every start. ALTER ROLE cannot take bound parameters, which once
broke every fresh self-hosted install at the migrate step.
"""

import importlib.util
import os
from pathlib import Path

import psycopg
import pytest
import settings

_MIGRATE_PY = Path(__file__).parent.parent.parent / "db-init" / "migrate.py"
_spec = importlib.util.spec_from_file_location("db_init_migrate", _MIGRATE_PY)
assert _spec is not None and _spec.loader is not None
migrate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migrate)


@pytest.fixture
def conn():
    with psycopg.connect(settings.DATABASE_URL, autocommit=True) as c:
        yield c


def test_statement_quotes_password_as_literal(conn):
    stmt = migrate.role_password_statement("appuser", "it's; DROP ROLE x; --")

    assert stmt.as_string(conn) == "ALTER ROLE \"appuser\" PASSWORD 'it''s; DROP ROLE x; --'"


def test_sync_runs_against_postgres(conn, monkeypatch):
    current_user = conn.execute("SELECT current_user").fetchone()[0]
    if current_user != "appuser":
        pytest.skip("needs to connect as appuser to reset its own password")

    # Re-set the current password so other test connections keep working
    monkeypatch.setenv("APPUSER_PASSWORD", os.environ["POSTGRES_PASSWORD"])

    migrate.sync_role_passwords(conn)

    with psycopg.connect(settings.DATABASE_URL) as fresh:
        assert fresh.execute("SELECT current_user").fetchone()[0] == "appuser"


def test_sync_skips_when_unset(monkeypatch):
    monkeypatch.delenv("APPUSER_PASSWORD", raising=False)

    class NoConn:
        def execute(self, *args, **kwargs):
            raise AssertionError("must not touch the database")

    migrate.sync_role_passwords(NoConn())
