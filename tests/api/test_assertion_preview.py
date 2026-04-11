"""API tests for downstream SP assertion preview endpoint."""

import pytest
from services.types import RequestingUser


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


@pytest.fixture
def test_sp(test_tenant, test_super_admin_user):
    """Create a test service provider."""
    from schemas.service_providers import SPCreate
    from services import service_providers as sp_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    return sp_service.create_service_provider(
        requesting_user,
        SPCreate(
            name="Preview Test SP",
        ),
    )


def test_assertion_preview_api(
    client,
    test_tenant_host,
    test_super_admin_user,
    test_user,
    test_sp,
    override_api_auth,
):
    override_api_auth(test_super_admin_user, level="super_admin")

    response = client.get(
        f"/api/v1/service-providers/{test_sp.id}/assertion-preview/{test_user['id']}",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["user_email"] == test_user["email"]
    assert data["user_first_name"] == "Test"
    assert data["user_last_name"] == "User"
    assert data["sp_name"] == "Preview Test SP"
    assert "email" in data["attributes"]
    assert "firstName" in data["attributes"]
    assert "name_id" in data
    assert "name_id_format" in data
    assert "has_access" in data
    assert "assertion_encrypted" in data


def test_assertion_preview_unauthorized(
    client, test_tenant_host, test_admin_user, test_user, test_sp, override_api_auth
):
    override_api_auth(test_admin_user, level="admin")

    response = client.get(
        f"/api/v1/service-providers/{test_sp.id}/assertion-preview/{test_user['id']}",
        headers={"Host": test_tenant_host},
    )

    # Admin-level override doesn't satisfy require_super_admin_api
    assert response.status_code in (401, 403)


def test_assertion_preview_sp_not_found(
    client, test_tenant_host, test_super_admin_user, test_user, override_api_auth
):
    from uuid import uuid4

    override_api_auth(test_super_admin_user, level="super_admin")

    response = client.get(
        f"/api/v1/service-providers/{uuid4()}/assertion-preview/{test_user['id']}",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 404


def test_assertion_preview_user_not_found(
    client, test_tenant_host, test_super_admin_user, test_sp, override_api_auth
):
    from uuid import uuid4

    override_api_auth(test_super_admin_user, level="super_admin")

    response = client.get(
        f"/api/v1/service-providers/{test_sp.id}/assertion-preview/{uuid4()}",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 404
