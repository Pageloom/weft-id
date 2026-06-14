"""Tests for the protected-domain (forward-auth) service layer.

Integration-style: runs against the real DB (with system_context autouse), with
DNS resolution mocked for verification. Covers registration, validation,
verification gating (the security-sensitive DNS path), deletion, event logging,
authorization, and the pre-auth host-admission helpers.
"""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import database
import dns.exception
import dns.resolver
import pytest
from schemas.protected_domains import ProtectedDomainCreate
from services import protected_domains as svc
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError


def _ru(user: dict, tenant_id: str, role: str = "super_admin") -> dict:
    return {"id": str(user["id"]), "tenant_id": str(tenant_id), "role": role}


def _register(user, tenant_id, domain="acme-corp.com", portal_host=None):
    portal_host = portal_host or f"auth.{domain}"
    return svc.register_protected_domain(
        _ru(user, tenant_id),
        ProtectedDomainCreate(domain=domain, portal_host=portal_host),
    )


# -- registration --------------------------------------------------------------


def test_register_creates_pending_domain_with_challenge(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="reg1.com")

    assert created.domain == "reg1.com"
    assert created.portal_host == "auth.reg1.com"
    assert created.verification_status == "pending"
    assert created.verification_token
    assert created.verification_record_name == "_weftid-challenge.reg1.com"
    assert created.verification_record_value == (
        "weftid-domain-verification=" + created.verification_token
    )


def test_register_logs_event(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="reg2.com")
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "protected_domain_registered"
    assert str(events[0]["artifact_id"]) == created.id


def test_register_normalizes_input(test_tenant, test_admin_user):
    created = svc.register_protected_domain(
        _ru(test_admin_user, test_tenant["id"]),
        ProtectedDomainCreate(domain="  REG3.COM. ", portal_host="AUTH.REG3.COM"),
    )
    assert created.domain == "reg3.com"
    assert created.portal_host == "auth.reg3.com"


def test_register_rejects_portal_host_not_under_domain(test_tenant, test_admin_user):
    with pytest.raises(ValidationError) as exc:
        svc.register_protected_domain(
            _ru(test_admin_user, test_tenant["id"]),
            ProtectedDomainCreate(domain="reg4.com", portal_host="auth.other.com"),
        )
    assert exc.value.code == "portal_host_not_under_domain"


def test_register_allows_apex_as_portal_host(test_tenant, test_admin_user):
    created = _register(
        test_admin_user, test_tenant["id"], domain="reg5.com", portal_host="reg5.com"
    )
    assert created.portal_host == "reg5.com"


def test_register_rejects_malformed_domain(test_tenant, test_admin_user):
    with pytest.raises(ValidationError):
        svc.register_protected_domain(
            _ru(test_admin_user, test_tenant["id"]),
            ProtectedDomainCreate(domain="nodot", portal_host="auth.nodot"),
        )


def test_register_duplicate_domain_conflicts(test_tenant, test_admin_user):
    _register(test_admin_user, test_tenant["id"], domain="dup.com")
    with pytest.raises(ConflictError) as exc:
        _register(test_admin_user, test_tenant["id"], domain="dup.com")
    assert exc.value.code == "protected_domain_exists"


def test_register_duplicate_portal_host_conflicts(test_tenant, test_admin_user):
    # First domain uses portal.shared.com as its portal host.
    svc.register_protected_domain(
        _ru(test_admin_user, test_tenant["id"]),
        ProtectedDomainCreate(domain="shared.com", portal_host="portal.shared.com"),
    )
    # Registering portal.shared.com itself as a protected domain with that same
    # host as its apex portal host collides on the globally-unique portal_host.
    with pytest.raises(ConflictError) as exc:
        svc.register_protected_domain(
            _ru(test_admin_user, test_tenant["id"]),
            ProtectedDomainCreate(domain="portal.shared.com", portal_host="portal.shared.com"),
        )
    assert exc.value.code == "portal_host_in_use"


@pytest.mark.parametrize("role", ["user", "admin"])
def test_register_requires_super_admin(test_tenant, test_user, role):
    # Protected domains are infra config (DNS/TLS/cookies); like SAML SP
    # management they are super_admin-only. A plain admin must be rejected too.
    with pytest.raises(ForbiddenError):
        svc.register_protected_domain(
            _ru(test_user, test_tenant["id"], role=role),
            ProtectedDomainCreate(domain="forbidden.com", portal_host="auth.forbidden.com"),
        )


# -- verification (DNS-TXT path) ----------------------------------------------


def test_verify_succeeds_when_txt_matches(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="verify1.com")
    expected = "weftid-domain-verification=" + created.verification_token

    with patch.object(svc, "_resolve_txt", return_value=["unrelated", expected]):
        result = svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)

    assert result.verified is True
    assert result.status == "verified"
    # Token cleared and verified_at set.
    fetched = svc.get_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert fetched.verification_status == "verified"
    assert fetched.verification_token is None
    assert fetched.verified_at is not None


def test_verify_logs_event_on_success(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="verify2.com")
    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "protected_domain_verified"


def test_verify_fails_when_record_missing(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="verify3.com")
    with patch.object(svc, "_resolve_txt", return_value=[]):
        result = svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert result.verified is False
    assert result.status == "failed"
    fetched = svc.get_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert fetched.verification_status == "failed"


def test_verify_fails_on_token_mismatch(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="verify4.com")
    with patch.object(svc, "_resolve_txt", return_value=["weftid-domain-verification=WRONG"]):
        result = svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert result.verified is False


def test_verify_idempotent_when_already_verified(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="verify5.com")
    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    # Second call must not even hit DNS.
    with patch.object(svc, "_resolve_txt", side_effect=AssertionError("DNS should not run")):
        result = svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert result.verified is True


def test_verify_can_succeed_after_prior_failure(test_tenant, test_admin_user):
    """Verification is re-runnable: a failed attempt can later succeed."""
    created = _register(test_admin_user, test_tenant["id"], domain="verify6.com")
    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        result = svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert result.verified is True


def test_verify_not_found(test_tenant, test_admin_user):
    with pytest.raises(NotFoundError):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), str(uuid4()))


def test_verify_requires_admin(test_tenant, test_admin_user, test_user):
    created = _register(test_admin_user, test_tenant["id"], domain="verify7.com")
    with pytest.raises(ForbiddenError):
        svc.verify_protected_domain(_ru(test_user, test_tenant["id"], role="user"), created.id)


# -- delete --------------------------------------------------------------------


def test_delete_removes_domain_and_logs(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="del1.com")
    svc.delete_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    with pytest.raises(NotFoundError):
        svc.get_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "protected_domain_deleted"


def test_delete_not_found(test_tenant, test_admin_user):
    with pytest.raises(NotFoundError):
        svc.delete_protected_domain(_ru(test_admin_user, test_tenant["id"]), str(uuid4()))


# -- list ----------------------------------------------------------------------


def test_list_returns_registered_domains(test_tenant, test_admin_user):
    _register(test_admin_user, test_tenant["id"], domain="list1.com")
    result = svc.list_protected_domains(_ru(test_admin_user, test_tenant["id"]))
    assert result.total >= 1
    assert any(d.domain == "list1.com" for d in result.items)


def test_list_requires_admin(test_tenant, test_user):
    with pytest.raises(ForbiddenError):
        svc.list_protected_domains(_ru(test_user, test_tenant["id"], role="user"))


# -- pre-auth host admission helpers (fail-closed) -----------------------------


def test_is_verified_portal_host_only_after_verification(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="admit1.com")
    # Pending: not admittable.
    assert svc.is_verified_portal_host("auth.admit1.com") is False

    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)

    assert svc.is_verified_portal_host("auth.admit1.com") is True
    # Case/format insensitive.
    assert svc.is_verified_portal_host("AUTH.ADMIT1.COM.") is True


def test_is_verified_portal_host_false_for_unknown(test_tenant):
    assert svc.is_verified_portal_host("nope.example.com") is False
    assert svc.is_verified_portal_host("") is False


def test_disabled_verified_domain_not_admittable(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="admit2.com")
    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert svc.is_verified_portal_host("auth.admit2.com") is True

    database.protected_domains.update_protected_domain(test_tenant["id"], created.id, enabled=False)
    assert svc.is_verified_portal_host("auth.admit2.com") is False


def test_resolve_verified_portal_host_returns_tenant(test_tenant, test_admin_user):
    created = _register(test_admin_user, test_tenant["id"], domain="admit3.com")
    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    row = svc.resolve_verified_portal_host("auth.admit3.com")
    assert row is not None
    assert str(row["tenant_id"]) == str(test_tenant["id"])
    assert row["domain"] == "admit3.com"


def test_multi_level_subdomain_of_portal_host_not_admitted(test_tenant, test_admin_user):
    """A deeper host under a verified portal host is NOT itself admitted.

    portal_host admission is an exact match on the globally-unique column, so a
    spoofed deeper label (evil.auth.<domain>) must fail closed even though its
    parent is verified.
    """
    created = _register(test_admin_user, test_tenant["id"], domain="spoof1.com")
    expected = "weftid-domain-verification=" + created.verification_token
    with patch.object(svc, "_resolve_txt", return_value=[expected]):
        svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)

    assert svc.is_verified_portal_host("auth.spoof1.com") is True
    assert svc.is_verified_portal_host("evil.auth.spoof1.com") is False
    # A sibling label that merely contains the verified host as a suffix string
    # but is a different host must also fail.
    assert svc.is_verified_portal_host("xauth.spoof1.com") is False


# -- _resolve_txt: real fail-closed DNS behavior --------------------------------
#
# Every test above mocks _resolve_txt. These exercise the real resolver wrapper
# (with dns.resolver.Resolver mocked) to prove it fails closed on every DNS
# error mode and decodes a real answer correctly.


def _resolver_raising(exc):
    """Build a fake Resolver whose resolve() raises *exc*."""
    fake = MagicMock()
    fake.resolve.side_effect = exc
    return MagicMock(return_value=fake)


@pytest.mark.parametrize(
    "exc",
    [
        dns.resolver.NXDOMAIN(),
        dns.resolver.NoAnswer(),
        dns.resolver.NoNameservers(),
        dns.exception.Timeout(),
        dns.exception.DNSException(),
    ],
)
def test_resolve_txt_fails_closed_on_dns_errors(exc):
    """Any DNS error yields an empty list (challenge treated as unsatisfied)."""
    with patch.object(svc.dns.resolver, "Resolver", _resolver_raising(exc)):
        assert svc._resolve_txt("_weftid-challenge.example.com") == []


def test_resolve_txt_decodes_answers():
    """A real TXT answer is decoded from its byte string chunks."""
    rdata = MagicMock()
    rdata.strings = [b"weftid-domain-verification=", b"abc123"]
    fake_resolver = MagicMock()
    fake_resolver.resolve.return_value = [rdata]
    with patch.object(svc.dns.resolver, "Resolver", MagicMock(return_value=fake_resolver)):
        result = svc._resolve_txt("_weftid-challenge.example.com")
    assert result == ["weftid-domain-verification=abc123"]


def test_verify_fails_closed_on_dns_timeout(test_tenant, test_admin_user):
    """An end-to-end verify with a DNS timeout marks the domain 'failed'."""
    created = _register(test_admin_user, test_tenant["id"], domain="dnsfail.com")
    with patch.object(svc.dns.resolver, "Resolver", _resolver_raising(dns.exception.Timeout())):
        result = svc.verify_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert result.verified is False
    assert result.status == "failed"


# -- cross-tenant isolation (migration 0047 RLS CASE branch) -------------------
#
# Migration 0047 relaxed the RLS policy so an UNSCOPED read (app.tenant_id unset)
# sees all rows -- required for the pre-auth portal-host lookup. These prove the
# SCOPED path is still strictly isolated: a tenant with app.tenant_id set must
# NOT see another tenant's protected domains.


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


def test_scoped_get_cannot_read_other_tenants_domain(test_tenant, test_admin_user, other_tenant):
    """A tenant admin cannot GET a protected domain owned by another tenant."""
    created = _register(test_admin_user, test_tenant["id"], domain="iso1.com")
    # An admin acting in other_tenant must not see it (RLS scoped read).
    with pytest.raises(NotFoundError):
        svc.get_protected_domain(_ru(test_admin_user, other_tenant["id"]), created.id)


def test_scoped_list_excludes_other_tenants_domain(test_tenant, test_admin_user, other_tenant):
    """List for one tenant never includes another tenant's domains."""
    _register(test_admin_user, test_tenant["id"], domain="iso2.com")
    result = svc.list_protected_domains(_ru(test_admin_user, other_tenant["id"]))
    assert all(d.domain != "iso2.com" for d in result.items)


def test_scoped_delete_cannot_remove_other_tenants_domain(
    test_tenant, test_admin_user, other_tenant
):
    """Delete scoped to the wrong tenant raises NotFound and leaves the row."""
    created = _register(test_admin_user, test_tenant["id"], domain="iso3.com")
    with pytest.raises(NotFoundError):
        svc.delete_protected_domain(_ru(test_admin_user, other_tenant["id"]), created.id)
    # Still present for the owning tenant.
    still = svc.get_protected_domain(_ru(test_admin_user, test_tenant["id"]), created.id)
    assert still.domain == "iso3.com"


def test_scoped_verify_cannot_touch_other_tenants_domain(
    test_tenant, test_admin_user, other_tenant
):
    """Verify scoped to the wrong tenant raises NotFound (no cross-tenant flip)."""
    created = _register(test_admin_user, test_tenant["id"], domain="iso4.com")
    with pytest.raises(NotFoundError):
        svc.verify_protected_domain(_ru(test_admin_user, other_tenant["id"]), created.id)


def test_duplicate_portal_host_across_tenants_conflicts(test_tenant, test_admin_user, other_tenant):
    """The globally-unique portal_host blocks reuse across tenants."""
    # Tenant A claims auth.shared-xt.com as the portal host under its domain.
    svc.register_protected_domain(
        _ru(test_admin_user, test_tenant["id"]),
        ProtectedDomainCreate(domain="shared-xt.com", portal_host="auth.shared-xt.com"),
    )
    # Tenant B registers that exact host as its own apex domain + portal host.
    # The portal_host column is globally unique, so this collides across tenants.
    with pytest.raises(ConflictError) as exc:
        svc.register_protected_domain(
            _ru(test_admin_user, other_tenant["id"]),
            ProtectedDomainCreate(domain="auth.shared-xt.com", portal_host="auth.shared-xt.com"),
        )
    assert exc.value.code == "portal_host_in_use"
