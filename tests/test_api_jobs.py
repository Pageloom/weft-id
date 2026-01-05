"""Tests for Background Jobs API endpoints."""

from uuid import uuid4

# =============================================================================
# List Jobs
# =============================================================================


def test_list_jobs_as_member(client, test_tenant_host, oauth2_authorization_header):
    """Any authenticated user can list their own jobs."""
    response = client.get(
        "/api/v1/jobs",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    assert "jobs" in data
    assert "has_active_jobs" in data
    assert isinstance(data["jobs"], list)
    assert isinstance(data["has_active_jobs"], bool)


def test_list_jobs_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can list their own jobs."""
    response = client.get(
        "/api/v1/jobs",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    assert "jobs" in data
    assert "has_active_jobs" in data


def test_list_jobs_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.get(
        "/api/v1/jobs",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Get Job
# =============================================================================


def test_get_job_not_found(client, test_tenant_host, oauth2_authorization_header):
    """Getting non-existent job returns 404."""
    fake_job_id = str(uuid4())
    response = client.get(
        f"/api/v1/jobs/{fake_job_id}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 404


def test_get_job_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    fake_job_id = str(uuid4())
    response = client.get(
        f"/api/v1/jobs/{fake_job_id}",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Delete Jobs
# =============================================================================


def test_delete_jobs_empty_list(client, test_tenant_host, oauth2_authorization_header):
    """Deleting empty list returns zero count."""
    response = client.request(
        "DELETE",
        "/api/v1/jobs",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"job_ids": []},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["deleted"] == 0


def test_delete_jobs_nonexistent(client, test_tenant_host, oauth2_authorization_header):
    """Deleting non-existent jobs returns zero count."""
    fake_job_ids = [str(uuid4()), str(uuid4())]
    response = client.request(
        "DELETE",
        "/api/v1/jobs",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"job_ids": fake_job_ids},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["deleted"] == 0


def test_delete_jobs_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.request(
        "DELETE",
        "/api/v1/jobs",
        headers={"Host": test_tenant_host},
        json={"job_ids": []},
    )

    assert response.status_code == 401


def test_delete_jobs_missing_body(client, test_tenant_host, oauth2_authorization_header):
    """Request without body fails validation."""
    response = client.request(
        "DELETE",
        "/api/v1/jobs",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 422
