"""API tests for SAML verbose assertion logging endpoints."""

import pytest
from schemas.saml import IdPCreate
from services.types import RequestingUser


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


@pytest.fixture
def test_idp(test_tenant, test_super_admin_user):
    """Create a test IdP for verbose logging API tests."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    return saml_service.create_identity_provider(
        requesting_user,
        IdPCreate(
            name="API Verbose Test IdP",
            provider_type="okta",
            entity_id="https://api-verbose-test.example.com/entity",
            sso_url="https://api-verbose-test.example.com/sso",
        ),
        base_url="https://test.weftid.localhost",
    )


def test_enable_verbose_logging_api(
    client, test_tenant_host, test_super_admin_user, test_idp, override_api_auth
):
    override_api_auth(test_super_admin_user, level="super_admin")

    response = client.post(
        f"/api/v1/saml/idps/{test_idp.id}/verbose-logging/enable",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["verbose_logging_enabled_at"] is not None
    assert data["verbose_logging_active"] is True


def test_disable_verbose_logging_api(
    client, test_tenant, test_tenant_host, test_super_admin_user, test_idp, override_api_auth
):
    from services import saml as saml_service

    # Enable first
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    saml_service.enable_verbose_logging(requesting_user, test_idp.id)

    override_api_auth(test_super_admin_user, level="super_admin")

    response = client.post(
        f"/api/v1/saml/idps/{test_idp.id}/verbose-logging/disable",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["verbose_logging_enabled_at"] is None
    assert data["verbose_logging_active"] is False


def test_enable_verbose_logging_unauthorized(
    client, test_tenant_host, test_admin_user, test_idp, override_api_auth
):
    override_api_auth(test_admin_user, level="admin")

    response = client.post(
        f"/api/v1/saml/idps/{test_idp.id}/verbose-logging/enable",
        headers={"Host": test_tenant_host},
    )

    # Admin-level override doesn't satisfy require_super_admin_api
    assert response.status_code in (401, 403)


def test_enable_verbose_logging_idp_not_found(
    client, test_tenant_host, test_super_admin_user, override_api_auth
):
    from uuid import uuid4

    override_api_auth(test_super_admin_user, level="super_admin")

    response = client.post(
        f"/api/v1/saml/idps/{uuid4()}/verbose-logging/enable",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 404
