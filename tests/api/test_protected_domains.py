"""Tests for the Protected Domains REST API endpoints.

These exercise the thin API layer (auth, request/response shape, error
translation) with the service layer mocked.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.protected_domains import (
    ProtectedDomain,
    ProtectedDomainList,
    ProtectedDomainVerifyResult,
)
from services.exceptions import ConflictError, NotFoundError


@pytest.fixture
def api_user():
    return {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "role": "super_admin",
        "email": "admin@test.com",
    }


@pytest.fixture
def api_host():
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_api_tenant(api_user):
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": api_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def pd_api_client(client, api_user, override_api_auth):
    override_api_auth(api_user, level="super_admin")
    return client


def _sample_domain(status="pending", token="tok-abc"):
    return ProtectedDomain(
        id=str(uuid4()),
        domain="acme-corp.com",
        portal_host="auth.acme-corp.com",
        verification_status=status,
        verification_token=token if status != "verified" else None,
        verification_record_name="_weftid-challenge.acme-corp.com",
        verification_record_value=(
            f"weftid-domain-verification={token}" if status != "verified" else None
        ),
        verified_at=datetime.now(UTC) if status == "verified" else None,
        enabled=True,
        created_at=datetime.now(UTC),
        created_by_name="Test Admin",
    )


class TestList:
    def test_list_success(self, pd_api_client, api_host):
        result = ProtectedDomainList(items=[_sample_domain()], total=1)
        with patch("services.protected_domains.list_protected_domains", return_value=result):
            resp = pd_api_client.get("/api/v1/protected-domains", headers={"Host": api_host})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["domain"] == "acme-corp.com"
        assert data["items"][0]["verification_record_name"] == "_weftid-challenge.acme-corp.com"


class TestRegister:
    def test_register_success(self, pd_api_client, api_host):
        with patch(
            "services.protected_domains.register_protected_domain",
            return_value=_sample_domain(),
        ):
            resp = pd_api_client.post(
                "/api/v1/protected-domains",
                headers={"Host": api_host},
                json={"domain": "acme-corp.com", "portal_host": "auth.acme-corp.com"},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["verification_status"] == "pending"
        assert data["verification_token"] == "tok-abc"

    def test_register_conflict_returns_409(self, pd_api_client, api_host):
        with patch(
            "services.protected_domains.register_protected_domain",
            side_effect=ConflictError(message="exists", code="protected_domain_exists"),
        ):
            resp = pd_api_client.post(
                "/api/v1/protected-domains",
                headers={"Host": api_host},
                json={"domain": "acme-corp.com", "portal_host": "auth.acme-corp.com"},
            )
        assert resp.status_code == 409

    def test_register_validation_error_on_missing_field(self, pd_api_client, api_host):
        resp = pd_api_client.post(
            "/api/v1/protected-domains",
            headers={"Host": api_host},
            json={"domain": "acme-corp.com"},
        )
        assert resp.status_code == 422


class TestVerify:
    def test_verify_success(self, pd_api_client, api_host):
        result = ProtectedDomainVerifyResult(verified=True, status="verified", message="ok")
        with patch("services.protected_domains.verify_protected_domain", return_value=result):
            resp = pd_api_client.post(
                f"/api/v1/protected-domains/{uuid4()}/verify", headers={"Host": api_host}
            )
        assert resp.status_code == 200
        assert resp.json()["verified"] is True

    def test_verify_failed_status(self, pd_api_client, api_host):
        result = ProtectedDomainVerifyResult(verified=False, status="failed", message="not found")
        with patch("services.protected_domains.verify_protected_domain", return_value=result):
            resp = pd_api_client.post(
                f"/api/v1/protected-domains/{uuid4()}/verify", headers={"Host": api_host}
            )
        assert resp.status_code == 200
        assert resp.json()["verified"] is False
        assert resp.json()["status"] == "failed"

    def test_verify_not_found_returns_404(self, pd_api_client, api_host):
        with patch(
            "services.protected_domains.verify_protected_domain",
            side_effect=NotFoundError(message="nope", code="protected_domain_not_found"),
        ):
            resp = pd_api_client.post(
                f"/api/v1/protected-domains/{uuid4()}/verify", headers={"Host": api_host}
            )
        assert resp.status_code == 404


class TestDelete:
    def test_delete_success(self, pd_api_client, api_host):
        with patch("services.protected_domains.delete_protected_domain") as mock_del:
            resp = pd_api_client.delete(
                f"/api/v1/protected-domains/{uuid4()}", headers={"Host": api_host}
            )
        assert resp.status_code == 204
        mock_del.assert_called_once()

    def test_delete_not_found_returns_404(self, pd_api_client, api_host):
        with patch(
            "services.protected_domains.delete_protected_domain",
            side_effect=NotFoundError(message="nope", code="protected_domain_not_found"),
        ):
            resp = pd_api_client.delete(
                f"/api/v1/protected-domains/{uuid4()}", headers={"Host": api_host}
            )
        assert resp.status_code == 404
