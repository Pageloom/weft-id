"""Tests for the proxy-app (forward-auth) service layer.

Integration-style: runs against the real DB (with system_context autouse).
Covers CRUD, the verified-domain gate, validation (URL/public-paths/header-config),
group grants, event logging, and super_admin authorization.
"""

from uuid import uuid4

import database
import pytest
from schemas.proxy_apps import ProxyAppCreate, ProxyAppUpdate
from services import proxy_apps as svc
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError


def _ru(user: dict, tenant_id: str, role: str = "super_admin") -> dict:
    return {"id": str(user["id"]), "tenant_id": str(tenant_id), "role": role}


def _create_domain(tenant_id, user_id, domain=None, status="verified"):
    domain = domain or f"{uuid4().hex[:8]}-acme.com"
    return database.protected_domains.create_protected_domain(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        domain=domain,
        portal_host=f"auth.{domain}",
        created_by=str(user_id),
        verification_status=status,
    )


def _create_group(tenant_id, name="Test Group", **kwargs):
    return database.groups.create_group(
        tenant_id=tenant_id, tenant_id_value=str(tenant_id), name=name, **kwargs
    )


def _make(user, tenant_id, domain_row, **overrides):
    data = ProxyAppCreate(
        protected_domain_id=str(domain_row["id"]),
        name=overrides.pop("name", "Grafana"),
        external_url=overrides.pop("external_url", f"https://grafana.{domain_row['domain']}"),
        **overrides,
    )
    return svc.create_proxy_app(_ru(user, tenant_id), data)


# -- create --------------------------------------------------------------------


def test_create_proxy_app(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    assert app.name == "Grafana"
    assert app.external_url == f"https://grafana.{domain['domain']}"
    assert app.domain == domain["domain"]
    assert app.enabled is True
    assert app.available_to_all is False


def test_create_logs_event(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "proxy_app_created"
    assert str(events[0]["artifact_id"]) == app.id


def test_create_requires_verified_domain(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"], status="pending")
    with pytest.raises(ValidationError) as exc:
        _make(test_admin_user, test_tenant["id"], domain)
    assert exc.value.code == "protected_domain_not_verified"


def test_create_unknown_domain_not_found(test_tenant, test_admin_user):
    with pytest.raises(NotFoundError):
        svc.create_proxy_app(
            _ru(test_admin_user, test_tenant["id"]),
            ProxyAppCreate(
                protected_domain_id=str(uuid4()),
                name="X",
                external_url="https://x.acme.com",
            ),
        )


def test_create_rejects_non_https_url(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError) as exc:
        _make(
            test_admin_user,
            test_tenant["id"],
            domain,
            external_url=f"http://grafana.{domain['domain']}",
        )
    assert exc.value.code == "invalid_external_url_scheme"


def test_create_rejects_url_host_not_under_domain(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError) as exc:
        _make(
            test_admin_user,
            test_tenant["id"],
            domain,
            external_url="https://grafana.evil.com",
        )
    assert exc.value.code == "external_url_not_under_domain"


def test_create_accepts_apex_host(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(
        test_admin_user,
        test_tenant["id"],
        domain,
        external_url=f"https://{domain['domain']}",
    )
    assert app.external_url == f"https://{domain['domain']}"


def test_create_validates_public_paths(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(
        test_admin_user,
        test_tenant["id"],
        domain,
        public_paths=["/health", " /public/* ", ""],
    )
    assert app.public_paths == ["/health", "/public/*"]


def test_create_rejects_unrooted_public_path(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError) as exc:
        _make(test_admin_user, test_tenant["id"], domain, public_paths=["health"])
    assert exc.value.code == "invalid_public_path"


def test_create_rejects_url_as_public_path(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError):
        _make(
            test_admin_user,
            test_tenant["id"],
            domain,
            public_paths=["//evil.com/x"],
        )


def test_create_accepts_supported_header_config(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(
        test_admin_user,
        test_tenant["id"],
        domain,
        header_config={"user": True, "email": True, "groups": False},
    )
    assert app.header_config == {"user": True, "email": True, "groups": False}


def test_create_rejects_unsupported_header_key(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError) as exc:
        _make(
            test_admin_user,
            test_tenant["id"],
            domain,
            header_config={"x-evil": True},
        )
    assert exc.value.code == "invalid_header_config"


# -- list / get ----------------------------------------------------------------


def test_list_and_get(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    listing = svc.list_proxy_apps(_ru(test_admin_user, test_tenant["id"]))
    assert listing.total >= 1
    assert any(a.id == app.id for a in listing.items)

    got = svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"]), app.id)
    assert got.id == app.id
    assert got.domain == domain["domain"]


def test_get_unknown_not_found(test_tenant, test_admin_user):
    with pytest.raises(NotFoundError):
        svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"]), str(uuid4()))


# -- update --------------------------------------------------------------------


def test_update_fields(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    updated = svc.update_proxy_app(
        _ru(test_admin_user, test_tenant["id"]),
        app.id,
        ProxyAppUpdate(
            name="Grafana 2",
            description="dashboards",
            public_paths=["/healthz"],
            header_config={"user": True},
            available_to_all=True,
            enabled=False,
        ),
    )
    assert updated.name == "Grafana 2"
    assert updated.description == "dashboards"
    assert updated.public_paths == ["/healthz"]
    assert updated.header_config == {"user": True}
    assert updated.available_to_all is True
    assert updated.enabled is False

    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "proxy_app_updated"


def test_update_validates_url(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(ValidationError):
        svc.update_proxy_app(
            _ru(test_admin_user, test_tenant["id"]),
            app.id,
            ProxyAppUpdate(external_url="https://grafana.evil.com"),
        )


def test_update_unknown_not_found(test_tenant, test_admin_user):
    with pytest.raises(NotFoundError):
        svc.update_proxy_app(
            _ru(test_admin_user, test_tenant["id"]),
            str(uuid4()),
            ProxyAppUpdate(name="X"),
        )


# -- delete --------------------------------------------------------------------


def test_delete(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    svc.delete_proxy_app(_ru(test_admin_user, test_tenant["id"]), app.id)
    with pytest.raises(NotFoundError):
        svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"]), app.id)
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "proxy_app_deleted"


def test_delete_unknown_not_found(test_tenant, test_admin_user):
    with pytest.raises(NotFoundError):
        svc.delete_proxy_app(_ru(test_admin_user, test_tenant["id"]), str(uuid4()))


# -- grants --------------------------------------------------------------------


def test_add_and_list_grant(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Grafana Users")

    grant = svc.add_proxy_app_grant(
        _ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"])
    )
    assert grant.group_id == str(group["id"])
    assert grant.group_name == "Grafana Users"

    grants = svc.list_proxy_app_grants(_ru(test_admin_user, test_tenant["id"]), app.id)
    assert grants.total == 1

    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "proxy_app_grant_added"


def test_add_grant_duplicate_conflicts(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Dup Group")
    svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"]))
    with pytest.raises(ConflictError):
        svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"]))


def test_add_grant_unknown_group_not_found(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(NotFoundError):
        svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(uuid4()))


def test_remove_grant(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Rm Group")
    svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"]))
    svc.remove_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"]))
    grants = svc.list_proxy_app_grants(_ru(test_admin_user, test_tenant["id"]), app.id)
    assert grants.total == 0
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "proxy_app_grant_removed"


def test_remove_grant_unknown_not_found(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(NotFoundError):
        svc.remove_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(uuid4()))


def test_available_groups_excludes_granted(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    g1 = _create_group(test_tenant["id"], name="Av1")
    g2 = _create_group(test_tenant["id"], name="Av2")
    svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(g1["id"]))
    available = svc.list_available_groups_for_proxy_app(
        _ru(test_admin_user, test_tenant["id"]), app.id
    )
    ids = {a["id"] for a in available}
    assert str(g2["id"]) in ids
    assert str(g1["id"]) not in ids


# -- authorization -------------------------------------------------------------


@pytest.mark.parametrize("role", ["user", "admin"])
def test_create_requires_super_admin(test_tenant, test_admin_user, role):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ForbiddenError):
        svc.create_proxy_app(
            _ru(test_admin_user, test_tenant["id"], role=role),
            ProxyAppCreate(
                protected_domain_id=str(domain["id"]),
                name="X",
                external_url=f"https://x.{domain['domain']}",
            ),
        )


@pytest.mark.parametrize("role", ["user", "admin"])
def test_list_requires_super_admin(test_tenant, test_admin_user, role):
    with pytest.raises(ForbiddenError):
        svc.list_proxy_apps(_ru(test_admin_user, test_tenant["id"], role=role))


def test_add_grant_requires_super_admin(test_tenant, test_admin_user):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Authz Group")
    with pytest.raises(ForbiddenError):
        svc.add_proxy_app_grant(
            _ru(test_admin_user, test_tenant["id"], role="admin"),
            app.id,
            str(group["id"]),
        )


# -- tenant isolation ----------------------------------------------------------


@pytest.fixture
def other_tenant():
    """A second, independent tenant for cross-tenant isolation checks."""
    unique_suffix = str(uuid4())[:8]
    subdomain = f"other-{unique_suffix}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": subdomain, "name": f"Other {unique_suffix}"},
    )
    tenant = database.fetchone(
        database.UNSCOPED,
        "SELECT id, subdomain, name FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    yield tenant
    database.execute(database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": tenant["id"]})


def test_get_other_tenant_app_not_found(test_tenant, test_admin_user, other_tenant):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(NotFoundError):
        svc.get_proxy_app(_ru(test_admin_user, other_tenant["id"]), app.id)


def test_update_other_tenant_app_not_found(test_tenant, test_admin_user, other_tenant):
    """A super_admin of another tenant cannot update this tenant's proxy app."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(NotFoundError):
        svc.update_proxy_app(
            _ru(test_admin_user, other_tenant["id"]),
            app.id,
            ProxyAppUpdate(name="Hijacked"),
        )
    # Confirm the app is untouched in its real tenant.
    still = svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"]), app.id)
    assert still.name == "Grafana"


def test_delete_other_tenant_app_not_found(test_tenant, test_admin_user, other_tenant):
    """A super_admin of another tenant cannot delete this tenant's proxy app."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(NotFoundError):
        svc.delete_proxy_app(_ru(test_admin_user, other_tenant["id"]), app.id)
    # App still exists in its real tenant.
    assert svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"]), app.id).id == app.id


def test_add_grant_other_tenant_app_not_found(test_tenant, test_admin_user, other_tenant):
    """Granting a group on another tenant's proxy app is rejected (app not visible)."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Cross Tenant Group")
    with pytest.raises(NotFoundError):
        svc.add_proxy_app_grant(_ru(test_admin_user, other_tenant["id"]), app.id, str(group["id"]))


def test_remove_grant_other_tenant_app_not_found(test_tenant, test_admin_user, other_tenant):
    """Removing a grant from another tenant's proxy app is rejected (app not visible)."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Cross Tenant Rm Group")
    svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"]))
    with pytest.raises(NotFoundError):
        svc.remove_proxy_app_grant(
            _ru(test_admin_user, other_tenant["id"]), app.id, str(group["id"])
        )
    # The grant survives in its real tenant.
    grants = svc.list_proxy_app_grants(_ru(test_admin_user, test_tenant["id"]), app.id)
    assert grants.total == 1


def test_create_against_other_tenant_domain_not_found(test_tenant, test_admin_user, other_tenant):
    """A domain verified in another tenant cannot be used to anchor a proxy app.

    The verified-domain gate is tenant-scoped: the domain row is invisible to
    this tenant, so the create fails with NotFoundError, not a successful
    cross-tenant attach.
    """
    other_domain = _create_domain(other_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError) as exc:
        svc.create_proxy_app(
            _ru(test_admin_user, test_tenant["id"]),
            ProxyAppCreate(
                protected_domain_id=str(other_domain["id"]),
                name="Cross",
                external_url=f"https://x.{other_domain['domain']}",
            ),
        )
    assert exc.value.code == "protected_domain_not_found"


# -- adversarial external-URL host-under-domain checks --------------------------


@pytest.fixture
def fixed_domain(test_tenant, test_admin_user):
    """A protected domain with a known apex ('acme.com') for suffix-trick probes."""
    return _create_domain(
        test_tenant["id"], test_admin_user["id"], domain=f"{uuid4().hex[:8]}.acme.com"
    )


@pytest.mark.parametrize(
    "bad_host_url",
    [
        # userinfo trick: real host is evil.com, not under the domain.
        "https://{apex}@evil.com/dashboard",
        # suffix-confusion: 'evil<domain>' is a different registrable name.
        "https://evil{apex}",
        # the domain appears as a left-label of an attacker domain.
        "https://{apex}.evil.com",
        "https://x.{apex}.evil.com",
        # bare attacker host.
        "https://grafana.example.org",
    ],
)
def test_create_rejects_host_outside_domain(
    test_tenant, test_admin_user, fixed_domain, bad_host_url
):
    """No URL whose effective host is outside the protected domain may be saved."""
    url = bad_host_url.format(apex=fixed_domain["domain"])
    with pytest.raises(ValidationError) as exc:
        _make(test_admin_user, test_tenant["id"], fixed_domain, external_url=url)
    assert exc.value.code in {
        "external_url_not_under_domain",
        "invalid_external_url",
    }


def test_create_accepts_userinfo_when_real_host_under_domain(
    test_tenant, test_admin_user, fixed_domain
):
    """Userinfo before an in-domain host is harmless: the host is what matters."""
    url = f"https://user:pw@grafana.{fixed_domain['domain']}/path"
    app = _make(test_admin_user, test_tenant["id"], fixed_domain, external_url=url)
    assert app.external_url == url


def test_create_host_match_is_case_insensitive(test_tenant, test_admin_user, fixed_domain):
    """An uppercase host under the domain is accepted (hosts are case-insensitive)."""
    app = _make(
        test_admin_user,
        test_tenant["id"],
        fixed_domain,
        external_url=f"https://GRAFANA.{fixed_domain['domain'].upper()}",
    )
    assert app.external_url.startswith("https://GRAFANA.")


def test_create_accepts_port_under_domain(test_tenant, test_admin_user, fixed_domain):
    """A port on an in-domain host does not defeat the host check."""
    url = f"https://grafana.{fixed_domain['domain']}:8443"
    app = _make(test_admin_user, test_tenant["id"], fixed_domain, external_url=url)
    assert app.external_url == url


def test_create_rejects_url_without_hostname(test_tenant, test_admin_user, fixed_domain):
    """A scheme-only / hostless https URL is rejected before the host check."""
    with pytest.raises(ValidationError) as exc:
        _make(test_admin_user, test_tenant["id"], fixed_domain, external_url="https:///path")
    assert exc.value.code == "invalid_external_url"


def test_update_url_rejects_host_outside_domain(test_tenant, test_admin_user, fixed_domain):
    """The host-under-domain check also guards the update path (userinfo trick)."""
    app = _make(test_admin_user, test_tenant["id"], fixed_domain)
    with pytest.raises(ValidationError):
        svc.update_proxy_app(
            _ru(test_admin_user, test_tenant["id"]),
            app.id,
            ProxyAppUpdate(external_url=f"https://{fixed_domain['domain']}@evil.com"),
        )
    # The original (in-domain) URL is unchanged.
    assert (
        svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"]), app.id).external_url
        == app.external_url
    )


# -- public-path and header-config edge cases ----------------------------------


def test_create_rejects_path_with_scheme(test_tenant, test_admin_user):
    """A public path containing '://' is rejected as a URL, not a path pattern."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError) as exc:
        _make(test_admin_user, test_tenant["id"], domain, public_paths=["/ok", "http://x/y"])
    assert exc.value.code == "invalid_public_path"


def test_create_rejects_path_with_space(test_tenant, test_admin_user):
    """A public path containing whitespace inside it is rejected."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError) as exc:
        _make(test_admin_user, test_tenant["id"], domain, public_paths=["/a b"])
    assert exc.value.code == "invalid_public_path"


def test_update_can_clear_public_paths_and_header_config(test_tenant, test_admin_user):
    """Passing empty collections on update clears the stored lists/maps."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(
        test_admin_user,
        test_tenant["id"],
        domain,
        public_paths=["/health"],
        header_config={"user": True},
    )
    updated = svc.update_proxy_app(
        _ru(test_admin_user, test_tenant["id"]),
        app.id,
        ProxyAppUpdate(public_paths=[], header_config={}),
    )
    assert updated.public_paths == []
    assert updated.header_config == {}


def test_update_rejects_unsupported_header_key(test_tenant, test_admin_user):
    """The supported-header-key gate also guards the update path."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(ValidationError) as exc:
        svc.update_proxy_app(
            _ru(test_admin_user, test_tenant["id"]),
            app.id,
            ProxyAppUpdate(header_config={"x-injected": True}),
        )
    assert exc.value.code == "invalid_header_config"


def test_header_config_coerces_truthy_values(test_tenant, test_admin_user):
    """Header-config values are normalized to booleans on the way in."""
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(
        test_admin_user,
        test_tenant["id"],
        domain,
        header_config={"user": True, "email": False},
    )
    assert app.header_config == {"user": True, "email": False}


# -- remaining authz coverage --------------------------------------------------


@pytest.mark.parametrize("role", ["user", "admin"])
def test_get_requires_super_admin(test_tenant, test_admin_user, role):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(ForbiddenError):
        svc.get_proxy_app(_ru(test_admin_user, test_tenant["id"], role=role), app.id)


@pytest.mark.parametrize("role", ["user", "admin"])
def test_update_requires_super_admin(test_tenant, test_admin_user, role):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(ForbiddenError):
        svc.update_proxy_app(
            _ru(test_admin_user, test_tenant["id"], role=role),
            app.id,
            ProxyAppUpdate(name="X"),
        )


@pytest.mark.parametrize("role", ["user", "admin"])
def test_delete_requires_super_admin(test_tenant, test_admin_user, role):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(ForbiddenError):
        svc.delete_proxy_app(_ru(test_admin_user, test_tenant["id"], role=role), app.id)


@pytest.mark.parametrize("role", ["user", "admin"])
def test_remove_grant_requires_super_admin(test_tenant, test_admin_user, role):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    group = _create_group(test_tenant["id"], name="Rm Authz Group")
    svc.add_proxy_app_grant(_ru(test_admin_user, test_tenant["id"]), app.id, str(group["id"]))
    with pytest.raises(ForbiddenError):
        svc.remove_proxy_app_grant(
            _ru(test_admin_user, test_tenant["id"], role=role), app.id, str(group["id"])
        )


@pytest.mark.parametrize("role", ["user", "admin"])
def test_list_grants_requires_super_admin(test_tenant, test_admin_user, role):
    domain = _create_domain(test_tenant["id"], test_admin_user["id"])
    app = _make(test_admin_user, test_tenant["id"], domain)
    with pytest.raises(ForbiddenError):
        svc.list_proxy_app_grants(_ru(test_admin_user, test_tenant["id"], role=role), app.id)
