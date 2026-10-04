"""Tests for migration 0080 (one OIDC link per user per connection).

The UNIQUE (idp_id, user_id) constraint is covered against the real table in
``tests/services/test_oidc_upstream_multi_link.py``. Duplicates can no longer
be inserted there, so the migration's clean-up statement runs here against a
temporary copy of the table.
"""

import re
from pathlib import Path
from uuid import uuid4

import database

_MIGRATION = (
    Path(__file__).parent.parent.parent
    / "db-init"
    / "migrations"
    / "0080_oidc_user_link_one_per_connection.sql"
)


def _dedupe_statement(table: str) -> str:
    sql = _MIGRATION.read_text()
    delete = re.search(r"DELETE FROM .*?;", sql, re.DOTALL)
    assert delete is not None
    return delete.group(0).replace("public.oidc_idp_user_links", table)


def test_dedupe_keeps_most_recently_used_then_newest():
    conn_a, conn_b, user_1, user_2 = (str(uuid4()) for _ in range(4))
    rows = [
        # user_1 on A: the used link wins over a newer unused one.
        ("a1-used", conn_a, user_1, "2026-01-01", "2026-03-01"),
        ("a1-newer-unused", conn_a, user_1, "2026-02-01", None),
        ("a1-older-used", conn_a, user_1, "2025-12-01", "2026-02-15"),
        # user_1 on B: nothing used, the newest wins.
        ("b1-old", conn_b, user_1, "2026-01-01", None),
        ("b1-new", conn_b, user_1, "2026-02-01", None),
        # user_2 on A: a single link is untouched.
        ("a2-only", conn_a, user_2, "2026-01-01", None),
    ]

    with database.session(tenant_id=database.UNSCOPED) as cur:
        cur.execute(
            """
            create temp table links_copy (
                id text primary key,
                idp_id text not null,
                user_id text not null,
                created_at timestamptz not null,
                last_used_at timestamptz
            ) on commit drop
            """
        )
        for row in rows:
            cur.execute("insert into links_copy values (%s, %s, %s, %s, %s)", row)

        cur.execute(_dedupe_statement("links_copy"))
        cur.execute("select id from links_copy order by id")
        survivors = [r["id"] for r in cur.fetchall()]

    assert survivors == ["a1-used", "a2-only", "b1-new"]
