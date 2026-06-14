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

    consumed = database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "acme-corp.com")

    assert consumed is not None
    assert consumed["nonce"] == nonce
    assert str(consumed["tenant_id"]) == str(tid)


def test_consume_nonce_second_time_is_rejected(test_tenant):
    """Double-spend: the second consume must return None."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce)

    first = database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "acme-corp.com")
    second = database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "acme-corp.com")

    assert first is not None
    assert second is None


def test_consume_unknown_nonce_returns_none(test_tenant):
    assert (
        database.forward_auth_nonces.consume_nonce(database.UNSCOPED, _mk_nonce(), "acme-corp.com")
        is None
    )


def test_consume_wrong_domain_returns_none(test_tenant):
    """A nonce minted for one domain cannot be consumed against another."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce, domain="acme-corp.com")

    wrong = database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "evil.com")
    assert wrong is None

    # The nonce is still present and consumable under the correct domain.
    right = database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "acme-corp.com")
    assert right is not None


def test_concurrent_consume_only_one_winner(test_tenant):
    """Under concurrent consumes of the same nonce, exactly one wins."""
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    _create(tid, nonce=nonce, domain="race.com")

    def attempt():
        return database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "race.com")

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
        missed = database.forward_auth_nonces.consume_nonce(other["id"], nonce, "scoped.com")
        assert missed is None

        # The original tenant scope still sees and consumes it.
        hit = database.forward_auth_nonces.consume_nonce(tid, nonce, "scoped.com")
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


def test_expired_unconsumed_nonce_is_still_consumable(test_tenant):
    """Expiry is enforced by token exp, not the nonce row -- consume ignores it.

    An expired-but-unconsumed nonce row must remain consumable at the DB layer
    (it is the cleanup job's job to purge it, and the token's own exp is what
    actually rejects a stale token in verify). consume_nonce has no expiry
    predicate, so it deletes the row regardless of expires_at.
    """
    tid = test_tenant["id"]
    nonce = _mk_nonce()
    # Born already-expired.
    database.forward_auth_nonces.create_nonce(
        tid, str(tid), nonce, "stale.com", datetime.now(UTC) - timedelta(seconds=10)
    )

    consumed = database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "stale.com")
    assert consumed is not None
    # And it is now gone (single-use still holds for expired rows).
    assert database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "stale.com") is None


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
        assert database.forward_auth_nonces.consume_nonce(tenant_b["id"], nonce, "iso.com") is None
        # A can still consume its own.
        assert database.forward_auth_nonces.consume_nonce(tid_a, nonce, "iso.com") is not None
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
    assert database.forward_auth_nonces.consume_nonce(tid, fresh, "acme-corp.com") is not None
    # The stale one was purged.
    assert database.forward_auth_nonces.consume_nonce(tid, stale, "acme-corp.com") is None


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

    assert (
        database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "acme-corp.com")
        is None
    )
