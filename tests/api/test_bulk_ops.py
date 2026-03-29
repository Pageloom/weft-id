"""Tests for bulk operations API endpoints."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

# =============================================================================
# POST /api/v1/users/bulk-ops/secondary-emails
# =============================================================================


def test_bulk_add_secondary_emails_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can create a bulk add secondary emails task."""
    user_id = str(uuid4())

    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_add_emails_task") as mock_create:
        mock_create.return_value = {
            "id": str(uuid4()),
            "created_at": datetime(2026, 3, 28, 10, 0, 0, tzinfo=UTC),
        }

        response = client.post(
            "/api/v1/users/bulk-ops/secondary-emails",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={
                "items": [
                    {"user_id": user_id, "email": "new@example.com"},
                ]
            },
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert "created_at" in data


def test_bulk_add_secondary_emails_unauthorized_member(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot create bulk add emails tasks."""
    response = client.post(
        "/api/v1/users/bulk-ops/secondary-emails",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={
            "items": [
                {"user_id": str(uuid4()), "email": "new@example.com"},
            ]
        },
    )

    assert response.status_code == 403


def test_bulk_add_secondary_emails_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.post(
        "/api/v1/users/bulk-ops/secondary-emails",
        headers={"Host": test_tenant_host},
        json={
            "items": [
                {"user_id": str(uuid4()), "email": "new@example.com"},
            ]
        },
    )

    assert response.status_code == 401


def test_bulk_add_secondary_emails_empty_items(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Empty items list returns 422 (Pydantic validation)."""
    response = client.post(
        "/api/v1/users/bulk-ops/secondary-emails",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"items": []},
    )

    assert response.status_code == 422


def test_bulk_add_secondary_emails_invalid_email(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Invalid email format returns 422."""
    response = client.post(
        "/api/v1/users/bulk-ops/secondary-emails",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "items": [
                {"user_id": str(uuid4()), "email": "not-an-email"},
            ]
        },
    )

    assert response.status_code == 422


def test_bulk_add_secondary_emails_missing_body(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Missing request body returns 422."""
    response = client.post(
        "/api/v1/users/bulk-ops/secondary-emails",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 422


# =============================================================================
# POST /api/v1/users/bulk-ops/primary-emails/preview
# =============================================================================


def test_bulk_primary_email_preview_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can create a bulk primary email preview task."""
    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_primary_email_preview_task"
    ) as mock_create:
        mock_create.return_value = {
            "id": str(uuid4()),
            "created_at": datetime(2026, 3, 28, 10, 0, 0, tzinfo=UTC),
        }

        response = client.post(
            "/api/v1/users/bulk-ops/primary-emails/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={
                "items": [
                    {"user_id": str(uuid4()), "new_primary_email": "new@example.com"},
                ]
            },
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data


def test_bulk_primary_email_preview_unauthorized(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot create preview tasks."""
    response = client.post(
        "/api/v1/users/bulk-ops/primary-emails/preview",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"items": [{"user_id": str(uuid4()), "new_primary_email": "new@example.com"}]},
    )

    assert response.status_code == 403


def test_bulk_primary_email_preview_empty_items(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Empty items returns 422."""
    response = client.post(
        "/api/v1/users/bulk-ops/primary-emails/preview",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"items": []},
    )

    assert response.status_code == 422


# =============================================================================
# POST /api/v1/users/bulk-ops/primary-emails/apply
# =============================================================================


def test_bulk_primary_email_apply_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can create a bulk primary email apply task."""
    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_primary_email_apply_task"
    ) as mock_create:
        mock_create.return_value = {
            "id": str(uuid4()),
            "created_at": datetime(2026, 3, 28, 10, 0, 0, tzinfo=UTC),
        }

        response = client.post(
            "/api/v1/users/bulk-ops/primary-emails/apply",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={
                "items": [
                    {
                        "user_id": str(uuid4()),
                        "new_primary_email": "new@example.com",
                        "idp_disposition": "keep",
                    },
                ],
                "preview_job_id": str(uuid4()),
            },
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data


def test_bulk_primary_email_apply_invalid_disposition(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Invalid idp_disposition value returns 422."""
    response = client.post(
        "/api/v1/users/bulk-ops/primary-emails/apply",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "items": [
                {
                    "user_id": str(uuid4()),
                    "new_primary_email": "new@example.com",
                    "idp_disposition": "invalid_value",
                },
            ],
            "preview_job_id": str(uuid4()),
        },
    )

    assert response.status_code == 422


# =============================================================================
# ServiceError paths
# =============================================================================


def test_bulk_add_secondary_emails_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from bg_tasks is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_add_emails_task") as mock_create:
        mock_create.side_effect = ServiceError(message="Task failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/secondary-emails",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"items": [{"user_id": str(uuid4()), "email": "new@example.com"}]},
        )

    assert response.status_code >= 400


def test_bulk_primary_email_preview_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from preview task is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_primary_email_preview_task"
    ) as mock_create:
        mock_create.side_effect = ServiceError(message="Preview failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/primary-emails/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"items": [{"user_id": str(uuid4()), "new_primary_email": "new@example.com"}]},
        )

    assert response.status_code >= 400


def test_bulk_primary_email_apply_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from apply task is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_primary_email_apply_task"
    ) as mock_create:
        mock_create.side_effect = ServiceError(message="Apply failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/primary-emails/apply",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={
                "items": [
                    {
                        "user_id": str(uuid4()),
                        "new_primary_email": "new@example.com",
                        "idp_disposition": "keep",
                    }
                ],
                "preview_job_id": str(uuid4()),
            },
        )

    assert response.status_code >= 400


# =============================================================================
# Null result (failed to create task)
# =============================================================================


def test_bulk_add_secondary_emails_null_result(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Null result from service returns error body."""
    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_add_emails_task") as mock_create:
        mock_create.return_value = None

        response = client.post(
            "/api/v1/users/bulk-ops/secondary-emails",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"items": [{"user_id": str(uuid4()), "email": "new@example.com"}]},
        )

    assert response.status_code == 202  # returns 202 but with error body
    assert "error" in response.json()


def test_bulk_primary_email_preview_null_result(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Null result from preview returns error body."""
    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_primary_email_preview_task"
    ) as mock_create:
        mock_create.return_value = None

        response = client.post(
            "/api/v1/users/bulk-ops/primary-emails/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"items": [{"user_id": str(uuid4()), "new_primary_email": "new@example.com"}]},
        )

    assert response.status_code == 202
    assert "error" in response.json()


def test_bulk_primary_email_apply_null_result(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Null result from apply returns error body."""
    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_primary_email_apply_task"
    ) as mock_create:
        mock_create.return_value = None

        response = client.post(
            "/api/v1/users/bulk-ops/primary-emails/apply",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={
                "items": [
                    {
                        "user_id": str(uuid4()),
                        "new_primary_email": "new@example.com",
                        "idp_disposition": "keep",
                    }
                ],
                "preview_job_id": str(uuid4()),
            },
        )

    assert response.status_code == 202
    assert "error" in response.json()
