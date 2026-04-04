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


# =============================================================================
# POST /api/v1/users/bulk-ops/inactivate
# =============================================================================


def test_bulk_inactivate_returns_202(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can create a bulk inactivate task and get 202."""
    user_id = str(uuid4())

    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_inactivate_task") as mock_create:
        mock_create.return_value = {
            "id": str(uuid4()),
            "created_at": datetime(2026, 3, 28, 10, 0, 0, tzinfo=UTC),
        }

        response = client.post(
            "/api/v1/users/bulk-ops/inactivate",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [user_id]},
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert "created_at" in data


def test_bulk_inactivate_requires_admin(client, test_tenant_host, oauth2_authorization_header):
    """Regular member cannot create bulk inactivate tasks."""
    response = client.post(
        "/api/v1/users/bulk-ops/inactivate",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"user_ids": [str(uuid4())]},
    )

    assert response.status_code == 403


def test_bulk_inactivate_empty_ids_returns_422(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Empty user_ids list returns 422 (Pydantic validation)."""
    response = client.post(
        "/api/v1/users/bulk-ops/inactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"user_ids": []},
    )

    assert response.status_code == 422


# =============================================================================
# POST /api/v1/users/bulk-ops/reactivate
# =============================================================================


def test_bulk_reactivate_returns_202(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can create a bulk reactivate task and get 202."""
    user_id = str(uuid4())

    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_reactivate_task") as mock_create:
        mock_create.return_value = {
            "id": str(uuid4()),
            "created_at": datetime(2026, 3, 28, 10, 0, 0, tzinfo=UTC),
        }

        response = client.post(
            "/api/v1/users/bulk-ops/reactivate",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [user_id]},
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert "created_at" in data


def test_bulk_reactivate_requires_admin(client, test_tenant_host, oauth2_authorization_header):
    """Regular member cannot create bulk reactivate tasks."""
    response = client.post(
        "/api/v1/users/bulk-ops/reactivate",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"user_ids": [str(uuid4())]},
    )

    assert response.status_code == 403


def test_bulk_reactivate_empty_ids_returns_422(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Empty user_ids list returns 422 (Pydantic validation)."""
    response = client.post(
        "/api/v1/users/bulk-ops/reactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"user_ids": []},
    )

    assert response.status_code == 422


# =============================================================================
# POST /api/v1/users/bulk-ops/group-assignment
# =============================================================================


def test_bulk_group_assignment_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can create a bulk group assignment task."""
    group_id = str(uuid4())
    user_ids = [str(uuid4()), str(uuid4())]

    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_group_assignment_task"
    ) as mock_create:
        mock_create.return_value = {
            "id": str(uuid4()),
            "created_at": datetime(2026, 4, 3, 10, 0, 0, tzinfo=UTC),
        }

        response = client.post(
            "/api/v1/users/bulk-ops/group-assignment",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"group_id": group_id, "user_ids": user_ids},
        )

    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert "created_at" in data


def test_bulk_group_assignment_unauthorized_member(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot create bulk group assignment tasks."""
    response = client.post(
        "/api/v1/users/bulk-ops/group-assignment",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"group_id": str(uuid4()), "user_ids": [str(uuid4())]},
    )

    assert response.status_code == 403


def test_bulk_group_assignment_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.post(
        "/api/v1/users/bulk-ops/group-assignment",
        headers={"Host": test_tenant_host},
        json={"group_id": str(uuid4()), "user_ids": [str(uuid4())]},
    )

    assert response.status_code == 401


def test_bulk_group_assignment_empty_user_ids(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Empty user_ids list returns 422 (Pydantic validation)."""
    response = client.post(
        "/api/v1/users/bulk-ops/group-assignment",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"group_id": str(uuid4()), "user_ids": []},
    )

    assert response.status_code == 422


def test_bulk_group_assignment_missing_group_id(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Missing group_id returns 422."""
    response = client.post(
        "/api/v1/users/bulk-ops/group-assignment",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"user_ids": [str(uuid4())]},
    )

    assert response.status_code == 422


# =============================================================================
# POST /api/v1/users/bulk-ops/group-assignment/preview
# =============================================================================


def test_bulk_group_assignment_preview_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can preview bulk group assignment."""
    group_id = str(uuid4())
    user_id = str(uuid4())

    with patch(
        "routers.api.v1.users.bg_tasks_service.preview_bulk_group_assignment"
    ) as mock_preview:
        mock_preview.return_value = {
            "eligible_ids": [user_id],
            "eligible": 1,
            "skipped": [],
            "group_id": group_id,
            "group_name": "Engineering",
        }

        response = client.post(
            "/api/v1/users/bulk-ops/group-assignment/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"group_id": group_id, "user_ids": [user_id]},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["eligible"] == 1
    assert data["group_name"] == "Engineering"


def test_bulk_group_assignment_preview_unauthorized(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot preview bulk group assignment."""
    response = client.post(
        "/api/v1/users/bulk-ops/group-assignment/preview",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"group_id": str(uuid4()), "user_ids": [str(uuid4())]},
    )

    assert response.status_code == 403


# =============================================================================
# Inactivate/Reactivate/GroupAssignment Preview Endpoints
# =============================================================================


def test_preview_bulk_inactivate_success(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can preview bulk inactivation."""
    user_id = str(uuid4())

    with patch("routers.api.v1.users.bg_tasks_service.preview_bulk_inactivate") as mock_preview:
        mock_preview.return_value = {
            "eligible_ids": [user_id],
            "eligible": 1,
            "skipped": [],
        }

        response = client.post(
            "/api/v1/users/bulk-ops/inactivate/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [user_id]},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["eligible"] == 1


def test_preview_bulk_inactivate_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from preview_bulk_inactivate is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch("routers.api.v1.users.bg_tasks_service.preview_bulk_inactivate") as mock_preview:
        mock_preview.side_effect = ServiceError(message="Failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/inactivate/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [str(uuid4())]},
        )

    assert response.status_code >= 400


def test_preview_bulk_reactivate_success(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can preview bulk reactivation."""
    user_id = str(uuid4())

    with patch("routers.api.v1.users.bg_tasks_service.preview_bulk_reactivate") as mock_preview:
        mock_preview.return_value = {
            "eligible_ids": [user_id],
            "eligible": 1,
            "skipped": [],
        }

        response = client.post(
            "/api/v1/users/bulk-ops/reactivate/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [user_id]},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["eligible"] == 1


def test_preview_bulk_reactivate_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from preview_bulk_reactivate is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch("routers.api.v1.users.bg_tasks_service.preview_bulk_reactivate") as mock_preview:
        mock_preview.side_effect = ServiceError(message="Failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/reactivate/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [str(uuid4())]},
        )

    assert response.status_code >= 400


# =============================================================================
# Null result + ServiceError for Inactivate/Reactivate/GroupAssignment
# =============================================================================


def test_bulk_inactivate_null_result(client, test_tenant_host, oauth2_admin_authorization_header):
    """Null result from inactivate service returns error body."""
    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_inactivate_task") as mock_create:
        mock_create.return_value = None

        response = client.post(
            "/api/v1/users/bulk-ops/inactivate",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [str(uuid4())]},
        )

    assert response.status_code == 202
    assert "error" in response.json()


def test_bulk_inactivate_service_error(client, test_tenant_host, oauth2_admin_authorization_header):
    """ServiceError from inactivate task is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_inactivate_task") as mock_create:
        mock_create.side_effect = ServiceError(message="Failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/inactivate",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [str(uuid4())]},
        )

    assert response.status_code >= 400


def test_bulk_reactivate_null_result(client, test_tenant_host, oauth2_admin_authorization_header):
    """Null result from reactivate service returns error body."""
    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_reactivate_task") as mock_create:
        mock_create.return_value = None

        response = client.post(
            "/api/v1/users/bulk-ops/reactivate",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [str(uuid4())]},
        )

    assert response.status_code == 202
    assert "error" in response.json()


def test_bulk_reactivate_service_error(client, test_tenant_host, oauth2_admin_authorization_header):
    """ServiceError from reactivate task is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch("routers.api.v1.users.bg_tasks_service.create_bulk_reactivate_task") as mock_create:
        mock_create.side_effect = ServiceError(message="Failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/reactivate",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"user_ids": [str(uuid4())]},
        )

    assert response.status_code >= 400


def test_bulk_group_assignment_null_result(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Null result from group assignment service returns error body."""
    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_group_assignment_task"
    ) as mock_create:
        mock_create.return_value = None

        response = client.post(
            "/api/v1/users/bulk-ops/group-assignment",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"group_id": str(uuid4()), "user_ids": [str(uuid4())]},
        )

    assert response.status_code == 202
    assert "error" in response.json()


def test_bulk_group_assignment_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from group assignment task is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch(
        "routers.api.v1.users.bg_tasks_service.create_bulk_group_assignment_task"
    ) as mock_create:
        mock_create.side_effect = ServiceError(message="Failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/group-assignment",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"group_id": str(uuid4()), "user_ids": [str(uuid4())]},
        )

    assert response.status_code >= 400


def test_bulk_group_assignment_preview_service_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """ServiceError from group assignment preview is translated to HTTP exception."""
    from services.exceptions import ServiceError

    with patch(
        "routers.api.v1.users.bg_tasks_service.preview_bulk_group_assignment"
    ) as mock_preview:
        mock_preview.side_effect = ServiceError(message="Failed", code="fail")

        response = client.post(
            "/api/v1/users/bulk-ops/group-assignment/preview",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
            json={"group_id": str(uuid4()), "user_ids": [str(uuid4())]},
        )

    assert response.status_code >= 400
