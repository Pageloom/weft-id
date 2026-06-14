"""Tests for database.protected_domains module.

Integration tests against a real database connection.
"""

from uuid import uuid4

import database


def _create_domain(tenant_id, user_id, domain="acme-corp.com", **kwargs):
    """Helper to create a protected domain with sensible defaults."""
    kwargs.setdefault("portal_host", f"auth.{domain}")
    return database.protected_domains.create_protected_domain(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        domain=domain,
        created_by=str(user_id),
        **kwargs,
    )


# -- create / get --------------------------------------------------------------


def test_create_protected_domain(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]

    row = _create_domain(tid, uid, domain="example.org", verification_token="tok-123")

    assert row is not None
    assert row["domain"] == "example.org"
    assert row["portal_host"] == "auth.example.org"
    assert row["verification_status"] == "pending"
    assert row["verification_token"] == "tok-123"
    assert row["verified_at"] is None
    assert row["enabled"] is True
    assert str(row["created_by"]) == str(uid)
    assert row["created_at"] is not None
    assert row["updated_at"] is not None


def test_get_protected_domain(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    created = _create_domain(tid, uid, domain="getme.com")

    fetched = database.protected_domains.get_protected_domain(tid, created["id"])

    assert fetched is not None
    assert fetched["id"] == created["id"]
    assert fetched["domain"] == "getme.com"


def test_get_protected_domain_not_found(test_tenant):
    tid = test_tenant["id"]
    assert database.protected_domains.get_protected_domain(tid, str(uuid4())) is None


def test_get_protected_domain_by_domain(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    _create_domain(tid, uid, domain="bydomain.com")

    fetched = database.protected_domains.get_protected_domain_by_domain(tid, "bydomain.com")

    assert fetched is not None
    assert fetched["domain"] == "bydomain.com"


def test_get_protected_domain_by_portal_host(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    _create_domain(tid, uid, domain="byhost.com", portal_host="auth.byhost.com")

    fetched = database.protected_domains.get_protected_domain_by_portal_host(tid, "auth.byhost.com")

    assert fetched is not None
    assert fetched["portal_host"] == "auth.byhost.com"


def test_create_duplicate_domain_raises(test_tenant, test_user):
    import psycopg.errors

    tid = test_tenant["id"]
    uid = test_user["id"]
    _create_domain(tid, uid, domain="dup.com", portal_host="auth.dup.com")

    try:
        _create_domain(tid, uid, domain="dup.com", portal_host="auth2.dup.com")
        assert False, "Expected UniqueViolation for duplicate (tenant, domain)"
    except psycopg.errors.UniqueViolation:
        pass


def test_create_duplicate_portal_host_raises(test_tenant, test_user):
    import psycopg.errors

    tid = test_tenant["id"]
    uid = test_user["id"]
    _create_domain(tid, uid, domain="a.com", portal_host="auth.shared.com")

    try:
        _create_domain(tid, uid, domain="b.com", portal_host="auth.shared.com")
        assert False, "Expected UniqueViolation for duplicate portal_host"
    except psycopg.errors.UniqueViolation:
        pass


# -- list ----------------------------------------------------------------------


def test_list_protected_domains(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    _create_domain(tid, uid, domain="one.com")
    _create_domain(tid, uid, domain="two.com")

    rows = database.protected_domains.list_protected_domains(tid)

    domains = {r["domain"] for r in rows}
    assert {"one.com", "two.com"} <= domains


def test_list_protected_domains_empty(test_tenant):
    tid = test_tenant["id"]
    assert database.protected_domains.list_protected_domains(tid) == []


# -- update --------------------------------------------------------------------


def test_update_protected_domain_verification(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    created = _create_domain(tid, uid, domain="verify.com")

    updated = database.protected_domains.update_protected_domain(
        tid,
        created["id"],
        verification_status="verified",
    )

    assert updated is not None
    assert updated["verification_status"] == "verified"


def test_update_protected_domain_ignores_unknown_fields(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    created = _create_domain(tid, uid, domain="ignore.com")

    # "domain" is not an allowed update field; should be ignored, no change.
    updated = database.protected_domains.update_protected_domain(
        tid, created["id"], domain="changed.com"
    )

    assert updated is not None
    assert updated["domain"] == "ignore.com"


def test_update_protected_domain_not_found(test_tenant):
    tid = test_tenant["id"]
    result = database.protected_domains.update_protected_domain(tid, str(uuid4()), enabled=False)
    assert result is None


def test_update_protected_domain_enabled_flag(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    created = _create_domain(tid, uid, domain="toggle.com")

    updated = database.protected_domains.update_protected_domain(tid, created["id"], enabled=False)

    assert updated["enabled"] is False


# -- delete --------------------------------------------------------------------


def test_delete_protected_domain(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    created = _create_domain(tid, uid, domain="delete.com")

    rows = database.protected_domains.delete_protected_domain(tid, created["id"])

    assert rows == 1
    assert database.protected_domains.get_protected_domain(tid, created["id"]) is None


def test_delete_protected_domain_not_found(test_tenant):
    tid = test_tenant["id"]
    assert database.protected_domains.delete_protected_domain(tid, str(uuid4())) == 0


# -- tenant isolation ----------------------------------------------------------


def test_protected_domains_tenant_isolation(test_tenant, test_user):
    """A domain created in one tenant is invisible to another tenant."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    created = _create_domain(tid, uid, domain="isolated.com", portal_host="auth.isolated.com")

    # Create a second, independent tenant.
    other = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other Tenant"},
    )
    try:
        assert database.protected_domains.get_protected_domain(other["id"], created["id"]) is None
        assert database.protected_domains.list_protected_domains(other["id"]) == []
    finally:
        database.execute(
            database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
        )
