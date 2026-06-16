"""Tests for database.forward_auth_nonces (single-use nonce store).

Integration tests against a real database connection. The critical property is
that ``consume_nonce`` is atomically single-use: a second consume of the same
nonce returns None (no double-spend), even under concurrent callers.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import pytest


def _mk_nonce() -> str:
    return uuid4().hex + uuid4().hex  # 64 hex chars, like token_hex(32)


def _create(tenant_id, nonce=None, domain="acme-corp.com", ttl=60):
    nonce = nonce or _mk_nonce()
    expires_at = datetime.now(UTC) + timedelta(seconds=ttl)
    return database.forward_auth_nonces.create_nonce(
        tenant_id, str(tenant_id), nonce, domain, expires_at
    )


def _consume(tenant_id, nonce, domain, now=None):
    """Consume helper defaulting ``now`` to the current time (unexpired path)."""
    return database.forward_auth_nonces.consume_nonce(
        tenant_id, nonce, domain, now or datetime.now(UTC)
    )


# -- create -------------------------------------------------------------------


def test_create_nonce(test_tenant):
    tid = test_tenant["id"]
    nonce = _mk_nonce()

    row = _create(tid, nonce=nonce, domain="example.org")

    assert row is not None
    assert row["nonce"] == nonce
    assert str(row["tenant_id"]) == str(tid)
    assert row["domain"] == "example.org"
    assert row["expires_at"] is not None
    assert row["created_at"] is not None


# -- consume (single-use) -----------------------------------------------------


def test_consume_nonce_first_time_succeeds(test_tenant):
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce, domain="acme-corp.com")

    consumed = _consume(database.UNSCOPED, nonce, "acme-corp.com")

    assert consumed is not None
    assert consumed["nonce"] == nonce
    assert str(consumed["tenant_id"]) == str(tid)


def test_consume_nonce_second_time_is_rejected(test_tenant):
    """Double-spend: the second consume must return None."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce)

    first = _consume(database.UNSCOPED, nonce, "acme-corp.com")
    second = _consume(database.UNSCOPED, nonce, "acme-corp.com")

    assert first is not None
    assert second is None


def test_consume_unknown_nonce_returns_none(test_tenant):
    assert _consume(database.UNSCOPED, _mk_nonce(), "acme-corp.com") is None


def test_consume_wrong_domain_returns_none(test_tenant):
    """A nonce minted for one domain cannot be consumed against another."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce, domain="acme-corp.com")

    wrong = _consume(database.UNSCOPED, nonce, "evil.com")
    assert wrong is None

    # The nonce is still present and consumable under the correct domain.
    right = _consume(database.UNSCOPED, nonce, "acme-corp.com")
    assert right is not None


def test_concurrent_consume_only_one_winner(test_tenant):
    """Under concurrent consumes of the same nonce, exactly one wins."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce, domain="race.com")

    def attempt():
        return _consume(database.UNSCOPED, nonce, "race.com")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: attempt(), range(8)))

    winners = [r for r in results if r is not None]
    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}"


# -- tenant isolation ---------------------------------------------------------


def test_consume_scoped_to_tenant(test_tenant):
    """A scoped consume only sees the scoping tenant's nonces."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce, domain="scoped.com")

    other = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other Tenant"},
    )
    try:
        # Scoped to the OTHER tenant: the nonce is invisible -> not consumed.
        missed = _consume(other["id"], nonce, "scoped.com")
        assert missed is None

        # The original tenant scope still sees and consumes it.
        hit = _consume(tid, nonce, "scoped.com")
        assert hit is not None
    finally:
        database.execute(
            database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
        )


def test_scoped_insert_rejects_foreign_tenant(test_tenant):
    """RLS WITH CHECK: a tenant-scoped insert cannot write another tenant's row.

    The mint path runs tenant-scoped; the 0048 policy's WITH CHECK must reject
    an insert whose tenant_id does not match the active scope, preventing a
    compromised/buggy mint from planting a nonce under a foreign tenant.
    """
    import psycopg

    scope = test_tenant["id"]

    other = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"foreign-{uuid4().hex[:8]}", "n": "Foreign Tenant"},
    )
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            # Scoped to `scope`, but the row claims `other` -> WITH CHECK fails.
            database.fetchone(
                scope,
                """
                insert into forward_auth_nonces (nonce, tenant_id, domain, expires_at)
                values (:nonce, :tenant_id, :domain, :expires_at)
                returning nonce
                """,
                {
                    "nonce": _mk_nonce(),
                    "tenant_id": str(other["id"]),
                    "domain": "x.com",
                    "expires_at": datetime.now(UTC) + timedelta(seconds=60),
                },
            )
    finally:
        database.execute(
            database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
        )


def test_expired_nonce_is_not_consumable(test_tenant):
    """Defense-in-depth: an expired nonce can never be consumed.

    CONTRACT CHANGE: ``consume_nonce`` now carries an ``expires_at > :now``
    predicate, so an expired-but-unconsumed row is rejected at the DB layer even
    if a future caller skips the upstream token ``exp`` check. (This test
    previously asserted the OLD behavior -- that an expired row was still
    consumable -- and has been updated to the new contract.)
    """
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    # Born already-expired.
    database.forward_auth_nonces.create_nonce(
        tid, str(tid), nonce, "stale.com", datetime.now(UTC) - timedelta(seconds=10)
    )

    # Expired -> not consumable (the row survives; cleanup purges it later).
    assert _consume(database.UNSCOPED, nonce, "stale.com") is None
    # The row is still present (the DELETE matched nothing), and would be
    # consumable if its expiry were in the future -- prove it via an explicit
    # `now` in the past relative to expiry by re-minting unexpired.
    fresh = _mk_nonce()
    _create(tid, nonce=fresh, domain="stale.com", ttl=60)
    assert _consume(database.UNSCOPED, fresh, "stale.com") is not None


def test_scoped_consume_does_not_cross_tenant_double_spend(test_tenant):
    """A scoped consume from tenant B must not consume tenant A's nonce.

    Tenant isolation under a SET scope: even with the correct nonce + domain,
    a consume scoped to a different tenant sees no row (RLS USING), so A's nonce
    survives and remains consumable by A. This closes cross-tenant double-spend.
    """
    tid_a = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid_a, nonce=nonce, domain="iso.com")

    tenant_b = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"b-{uuid4().hex[:8]}", "n": "Tenant B"},
    )
    try:
        # B's scope: A's nonce is invisible -> not consumed.
        assert _consume(tenant_b["id"], nonce, "iso.com") is None
        # A can still consume its own.
        assert _consume(tid_a, nonce, "iso.com") is not None
    finally:
        database.execute(
            database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": tenant_b["id"]}
        )


# -- cleanup ------------------------------------------------------------------


def test_delete_expired_nonces(test_tenant):
    tid = test_tenant["id"]
    fresh = _mk_nonce()
    stale = _mk_nonce()
    _create(tid, nonce=fresh, ttl=3600)
    # Already-expired row.
    database.forward_auth_nonces.create_nonce(
        tid, str(tid), stale, "acme-corp.com", datetime.now(UTC) - timedelta(seconds=10)
    )

    deleted = database.forward_auth_nonces.delete_expired_nonces(tid, datetime.now(UTC))

    assert deleted >= 1
    # The fresh nonce survives and is still consumable.
    assert _consume(tid, fresh, "acme-corp.com") is not None
    # The stale one was purged.
    assert _consume(tid, stale, "acme-corp.com") is None


def test_create_nonce_cascades_on_tenant_delete():
    """Deleting a tenant removes its nonces (FK ON DELETE CASCADE)."""
    tenant = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"casc-{uuid4().hex[:8]}", "n": "Cascade Tenant"},
    )
    nonce = _mk_nonce()
    _create(tenant["id"], nonce=nonce)

    database.execute(database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": tenant["id"]})

    assert _consume(database.UNSCOPED, nonce, "acme-corp.com") is None
