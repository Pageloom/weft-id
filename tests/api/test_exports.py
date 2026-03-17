"""Tests for Exports API endpoints."""

import tempfile
from unittest.mock import patch
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


def test_list_exports_unauthorized_member(client, test_tenant_host, oauth2_authorization_header):
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


def test_create_export_unauthorized_member(client, test_tenant_host, oauth2_authorization_header):
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


def test_download_export_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Downloading non-existent export returns 404."""
    fake_export_id = str(uuid4())
    response = client.get(
        f"/api/v1/exports/{fake_export_id}/download",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404


def test_download_export_unauthorized_member(client, test_tenant_host, oauth2_authorization_header):
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


def test_download_export_local_storage(client, test_tenant_host, oauth2_admin_authorization_header):
    """Downloading export from local storage returns the file directly."""
    export_id = str(uuid4())

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        f.write(b"event_id,event_type\n1,user_created\n")
        tmp_path = f.name

    download_info = {
        "storage_type": "local",
        "path": tmp_path,
        "filename": "export.csv",
        "content_type": "text/csv",
    }

    with patch("routers.api.v1.exports.exports_service.get_download", return_value=download_info):
        response = client.get(
            f"/api/v1/exports/{export_id}/download",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        )

    assert response.status_code == 200
    assert b"event_id,event_type" in response.content


def test_download_export_spaces_redirect(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Downloading export from cloud storage returns a redirect."""
    export_id = str(uuid4())
    signed_url = "https://spaces.example.com/exports/file.csv?token=abc"

    download_info = {
        "storage_type": "spaces",
        "url": signed_url,
    }

    with patch("routers.api.v1.exports.exports_service.get_download", return_value=download_info):
        response = client.get(
            f"/api/v1/exports/{export_id}/download",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            follow_redirects=False,
        )

    assert response.status_code == 307
    assert response.headers["location"] == signed_url


def test_create_export_service_error(client, test_tenant_host, oauth2_admin_authorization_header):
    """Create export returns error when service raises ServiceError."""
    from services.exceptions import ServiceError

    with patch(
        "routers.api.v1.exports.bg_tasks_service.create_export_task",
        side_effect=ServiceError(message="Export failed", code="export_error"),
    ):
        response = client.post(
            "/api/v1/exports",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "Export failed"


def test_create_export_returns_error_when_task_creation_fails(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Create export returns 500 when bg task creation returns None."""
    with patch(
        "routers.api.v1.exports.bg_tasks_service.create_export_task",
        return_value=None,
    ):
        response = client.post(
            "/api/v1/exports",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        )

    assert response.status_code == 500
    assert "Failed to create export task" in response.json()["detail"]


def test_list_exports_service_error(client, test_tenant_host, oauth2_admin_authorization_header):
    """List exports returns error when service raises."""
    from services.exceptions import ServiceError

    with patch(
        "routers.api.v1.exports.exports_service.list_exports",
        side_effect=ServiceError(message="DB error", code="db_error"),
    ):
        response = client.get(
            "/api/v1/exports",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        )

    assert response.status_code == 500
