"""Tests for Exports API endpoints."""

from uuid import uuid4

# =============================================================================
# List Exports
# =============================================================================


def test_list_exports_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can list exports."""
    response = client.get(
        "/api/v1/exports",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)
    assert isinstance(data["total"], int)


def test_list_exports_unauthorized_member(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot list exports."""
    response = client.get(
        "/api/v1/exports",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_list_exports_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.get(
        "/api/v1/exports",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Create Export
# =============================================================================


def test_create_export_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can create export task."""
    response = client.post(
        "/api/v1/exports",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert data["job_type"] == "export_events"
    assert data["status"] == "pending"


def test_create_export_unauthorized_member(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot create exports."""
    response = client.post(
        "/api/v1/exports",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_create_export_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.post(
        "/api/v1/exports",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Download Export
# =============================================================================


def test_download_export_not_found(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Downloading non-existent export returns 404."""
    fake_export_id = str(uuid4())
    response = client.get(
        f"/api/v1/exports/{fake_export_id}/download",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404


def test_download_export_unauthorized_member(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot download exports."""
    fake_export_id = str(uuid4())
    response = client.get(
        f"/api/v1/exports/{fake_export_id}/download",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_download_export_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    fake_export_id = str(uuid4())
    response = client.get(
        f"/api/v1/exports/{fake_export_id}/download",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401
