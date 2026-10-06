"""Tests for migration 0080 (one OIDC link per user per connection).

The UNIQUE (idp_id, user_id) constraint is covered against the real table in
``tests/services/test_oidc_upstream_multi_link.py``. Duplicates can no longer
be inserted there, so the clean-up's ranking runs here over inline rows. The
test role has no TEMP privilege (as in production), so no scratch table.
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


# Typed VALUES list standing in for the table inside the ranking subquery.
_ROWS_SOURCE = """(
    SELECT id, idp_id, user_id, created_at::timestamptz, last_used_at::timestamptz
    FROM (VALUES {values}) AS v(id, idp_id, user_id, created_at, last_used_at)
) AS rows"""


def _ranking_subquery() -> str:
    """The migration's ``USING (...) ranked`` subquery, verbatim."""
    sql = _MIGRATION.read_text()
    ranked = re.search(r"USING \((.*?)\) ranked", sql, re.DOTALL)
    assert ranked is not None
    return ranked.group(1)


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

    values = ", ".join(["(%s, %s, %s, %s, %s)"] * len(rows))
    ranked = _ranking_subquery().replace(
        "public.oidc_idp_user_links", _ROWS_SOURCE.format(values=values)
    )
    params = [field for row in rows for field in row]

    # The migration deletes every row ranked above 1; keep the rest.
    with database.session(tenant_id=database.UNSCOPED) as cur:
        cur.execute(f"select id from ({ranked}) ranked where rn = 1 order by id", params)
        survivors = [r["id"] for r in cur.fetchall()]

    assert survivors == ["a1-used", "a2-only", "b1-new"]
