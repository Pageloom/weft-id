"""Tests for database.proxy_apps module.

Integration tests against a real database connection.
"""

from uuid import uuid4

import database


def _create_domain(tenant_id, user_id, domain=None, **kwargs):
    domain = domain or f"{uuid4().hex[:8]}.example.com"
    kwargs.setdefault("portal_host", f"auth.{domain}")
    return database.protected_domains.create_protected_domain(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        domain=domain,
        created_by=str(user_id),
        **kwargs,
    )


def _create_app(tenant_id, user_id, domain_id, name="Grafana", **kwargs):
    kwargs.setdefault("external_url", "https://grafana.acme-corp.com")
    return database.proxy_apps.create_proxy_app(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        protected_domain_id=domain_id,
        name=name,
        created_by=str(user_id),
        **kwargs,
    )


# -- create / get --------------------------------------------------------------


def test_create_proxy_app(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)

    row = _create_app(
        tid,
        uid,
        domain["id"],
        name="Sonarr",
        description="Media manager",
        public_paths=["/login", "/health"],
        header_config={"user": True, "email": True},
        available_to_all=True,
    )

    assert row is not None
    assert row["name"] == "Sonarr"
    assert row["description"] == "Media manager"
    assert str(row["protected_domain_id"]) == str(domain["id"])
    assert row["external_url"] == "https://grafana.acme-corp.com"
    assert row["public_paths"] == ["/login", "/health"]
    assert row["header_config"] == {"user": True, "email": True}
    assert row["available_to_all"] is True
    assert row["enabled"] is True
    assert str(row["created_by"]) == str(uid)


def test_create_proxy_app_jsonb_defaults(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)

    row = _create_app(tid, uid, domain["id"], name="Defaults App")

    assert row["public_paths"] == []
    assert row["header_config"] == {}
    assert row["available_to_all"] is False


def test_get_proxy_app(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    created = _create_app(tid, uid, domain["id"])

    fetched = database.proxy_apps.get_proxy_app(tid, created["id"])

    assert fetched is not None
    assert fetched["id"] == created["id"]


def test_get_proxy_app_not_found(test_tenant):
    tid = test_tenant["id"]
    assert database.proxy_apps.get_proxy_app(tid, str(uuid4())) is None


# -- list ----------------------------------------------------------------------


def test_list_proxy_apps(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    _create_app(tid, uid, domain["id"], name="App One")
    _create_app(tid, uid, domain["id"], name="App Two")

    rows = database.proxy_apps.list_proxy_apps(tid)

    names = {r["name"] for r in rows}
    assert {"App One", "App Two"} <= names


def test_list_proxy_apps_for_domain(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain_a = _create_domain(tid, uid)
    domain_b = _create_domain(tid, uid)
    _create_app(tid, uid, domain_a["id"], name="Alpha")
    _create_app(tid, uid, domain_a["id"], name="Beta")
    _create_app(tid, uid, domain_b["id"], name="Gamma")

    rows = database.proxy_apps.list_proxy_apps_for_domain(tid, domain_a["id"])

    names = [r["name"] for r in rows]
    assert names == ["Alpha", "Beta"]  # ordered by name


def test_list_proxy_apps_empty(test_tenant):
    tid = test_tenant["id"]
    assert database.proxy_apps.list_proxy_apps(tid) == []


# -- update --------------------------------------------------------------------


def test_update_proxy_app_scalar_fields(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    created = _create_app(tid, uid, domain["id"], name="Old Name")

    updated = database.proxy_apps.update_proxy_app(
        tid, created["id"], name="New Name", available_to_all=True, enabled=False
    )

    assert updated["name"] == "New Name"
    assert updated["available_to_all"] is True
    assert updated["enabled"] is False


def test_update_proxy_app_jsonb_fields(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    created = _create_app(tid, uid, domain["id"])

    updated = database.proxy_apps.update_proxy_app(
        tid,
        created["id"],
        public_paths=["/api/health"],
        header_config={"groups": True},
    )

    assert updated["public_paths"] == ["/api/health"]
    assert updated["header_config"] == {"groups": True}


def test_update_proxy_app_ignores_unknown_fields(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    created = _create_app(tid, uid, domain["id"])

    # "protected_domain_id" is not an allowed update field; should be ignored.
    original_domain_id = str(created["protected_domain_id"])
    updated = database.proxy_apps.update_proxy_app(
        tid, created["id"], protected_domain_id=str(uuid4())
    )

    assert str(updated["protected_domain_id"]) == original_domain_id


def test_update_proxy_app_not_found(test_tenant):
    tid = test_tenant["id"]
    assert database.proxy_apps.update_proxy_app(tid, str(uuid4()), name="x") is None


# -- delete --------------------------------------------------------------------


def test_delete_proxy_app(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    created = _create_app(tid, uid, domain["id"])

    rows = database.proxy_apps.delete_proxy_app(tid, created["id"])

    assert rows == 1
    assert database.proxy_apps.get_proxy_app(tid, created["id"]) is None


def test_delete_proxy_app_not_found(test_tenant):
    tid = test_tenant["id"]
    assert database.proxy_apps.delete_proxy_app(tid, str(uuid4())) == 0


def test_deleting_domain_cascades_to_proxy_apps(test_tenant, test_user):
    """Deleting a protected domain cascades to its proxy apps."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    app = _create_app(tid, uid, domain["id"])

    database.protected_domains.delete_protected_domain(tid, domain["id"])

    assert database.proxy_apps.get_proxy_app(tid, app["id"]) is None


# -- tenant isolation ----------------------------------------------------------


def test_proxy_apps_tenant_isolation(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    app = _create_app(tid, uid, domain["id"])

    other = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other Tenant"},
    )
    try:
        assert database.proxy_apps.get_proxy_app(other["id"], app["id"]) is None
        assert database.proxy_apps.list_proxy_apps(other["id"]) == []
    finally:
        database.execute(
            database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
        )


# -- host resolution (forward-auth /check hot path) ----------------------------


def test_get_enabled_app_by_host_exact_match(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    app = _create_app(tid, uid, domain["id"], external_url="https://grafana.acme-corp.com")

    found = database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
        tid, domain["id"], "grafana.acme-corp.com"
    )
    assert found is not None
    assert str(found["id"]) == str(app["id"])


def test_get_enabled_app_by_host_with_path_in_url(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    app = _create_app(tid, uid, domain["id"], external_url="https://grafana.acme-corp.com/app")

    found = database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
        tid, domain["id"], "grafana.acme-corp.com"
    )
    assert found is not None
    assert str(found["id"]) == str(app["id"])


def test_get_enabled_app_by_host_no_substring_confusion(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    _create_app(tid, uid, domain["id"], external_url="https://grafana.acme-corp.com")

    # A host that is a prefix of the registered one must not match.
    assert (
        database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
            tid, domain["id"], "grafana.acme-corp.co"
        )
        is None
    )
    # A host that contains the registered one as a suffix must not match.
    assert (
        database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
            tid, domain["id"], "evilgrafana.acme-corp.com"
        )
        is None
    )


def test_get_enabled_app_by_host_excludes_disabled(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    domain = _create_domain(tid, uid)
    _create_app(tid, uid, domain["id"], external_url="https://grafana.acme-corp.com", enabled=False)

    assert (
        database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
            tid, domain["id"], "grafana.acme-corp.com"
        )
        is None
    )
