"""Unit tests for User Management API endpoints.

These tests use FastAPI dependency overrides and mocks to isolate the API layer.
For integration tests that use real services, see tests/integration/.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from api_dependencies import get_current_user_api, require_admin_api, require_super_admin_api
from dependencies import get_tenant_id_from_request
from main import app
from schemas.api import (
    BackupCodesResponse,
    BackupCodesStatusResponse,
    EmailInfo,
    MFAStatus,
    TOTPSetupResponse,
    UserDetail,
    UserListResponse,
    UserSummary,
)
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from starlette.testclient import TestClient

# =============================================================================
# Roles
# =============================================================================


def test_list_roles_as_admin(make_user_dict):
    """Admin can list available roles."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_available_roles.return_value = ["member", "admin", "super_admin"]

        client = TestClient(app)
        response = client.get("/api/v1/users/roles")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        assert response.json() == ["member", "admin", "super_admin"]


# Note: Authorization tests (e.g., member cannot list roles) are better covered
# in integration tests where the full auth flow is tested. Unit tests focus on
# testing the business logic when auth is satisfied.
# =============================================================================
# User List
# =============================================================================


def test_list_users_as_admin(make_user_dict):
    """Test listing users as admin."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    mock_response = UserListResponse(
        items=[
            UserSummary(
                id=str(uuid4()),
                email="user@example.com",
                first_name="Test",
                last_name="User",
                role="member",
                created_at=datetime.now(UTC),
                last_login=None,
                last_activity_at=None,
                is_inactivated=False,
                is_anonymized=False,
            )
        ],
        total=1,
        page=1,
        limit=25,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/users")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert data["page"] == 1
        assert data["limit"] == 25
        assert data["total"] == 1


def test_list_users_with_pagination(make_user_dict):
    """Test listing users with pagination parameters."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    mock_response = UserListResponse(items=[], total=0, page=1, limit=5)

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/users?page=1&limit=5")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["limit"] == 5


# Note: test_list_users_unauthorized is covered in integration tests


def test_get_user_as_admin(make_user_dict):
    """Test getting a user's details as admin."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    target_user_id = str(uuid4())

    mock_detail = UserDetail(
        id=target_user_id,
        email="target@example.com",
        first_name="Target",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[
            EmailInfo(
                id=str(uuid4()),
                email="target@example.com",
                is_primary=True,
                verified_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        ],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == target_user_id
        assert data["first_name"] == "Target"
        assert data["last_name"] == "User"
        assert "emails" in data
        assert "is_service_user" in data


def test_get_user_not_found(make_user_dict):
    """Test getting a non-existent user."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    fake_id = "00000000-0000-0000-0000-000000000000"

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(f"/api/v1/users/{fake_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 404


def test_create_user_as_admin(make_user_dict):
    """Test creating a new user as admin."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    new_user_id = str(uuid4())

    mock_detail = UserDetail(
        id=new_user_id,
        email="newuser@test.example.com",
        first_name="New",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[
            EmailInfo(
                id=str(uuid4()),
                email="newuser@test.example.com",
                is_primary=True,
                verified_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        ],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.create_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(
            "/api/v1/users",
            json={
                "first_name": "New",
                "last_name": "User",
                "email": "newuser@test.example.com",
                "role": "member",
            },
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "New"
        assert data["last_name"] == "User"
        assert data["role"] == "member"
        assert len(data["emails"]) == 1
        assert data["emails"][0]["email"] == "newuser@test.example.com"
        assert data["emails"][0]["is_primary"] is True


def test_create_user_duplicate_email(make_user_dict):
    """Test creating a user with duplicate email."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.create_user.side_effect = ConflictError(
            message="Email already exists", code="email_exists"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/users",
            json={
                "first_name": "Duplicate",
                "last_name": "User",
                "email": "existing@example.com",
                "role": "member",
            },
        )

        app.dependency_overrides.clear()

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]


def test_create_user_as_super_admin_with_super_admin_role(make_user_dict):
    """Test that super_admin can create users with super_admin role."""
    super_admin = make_user_dict(role="super_admin")
    tenant_id = super_admin["tenant_id"]
    new_user_id = str(uuid4())

    mock_detail = UserDetail(
        id=new_user_id,
        email="newsuperadmin@test.example.com",
        first_name="New",
        last_name="SuperAdmin",
        role="super_admin",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[
            EmailInfo(
                id=str(uuid4()),
                email="newsuperadmin@test.example.com",
                is_primary=True,
                verified_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        ],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
    )

    app.dependency_overrides[require_admin_api] = lambda: super_admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.create_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(
            "/api/v1/users",
            json={
                "first_name": "New",
                "last_name": "SuperAdmin",
                "email": "newsuperadmin@test.example.com",
                "role": "super_admin",
            },
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        data = response.json()
        assert data["role"] == "super_admin"


def test_create_user_admin_cannot_create_super_admin(make_user_dict):
    """Test that regular admin cannot create users with super_admin role."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.create_user.side_effect = ForbiddenError(
            message="Only super_admin can create users with super_admin role",
            code="role_escalation_denied",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/users",
            json={
                "first_name": "New",
                "last_name": "SuperAdmin",
                "email": "cannotcreate@test.example.com",
                "role": "super_admin",
            },
        )

        app.dependency_overrides.clear()

        assert response.status_code == 403
        assert "Only super_admin" in response.json()["detail"]


def test_update_user_name(make_user_dict):
    """Test updating a user's name."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    mock_detail = UserDetail(
        id=user_id,
        email="user@example.com",
        first_name="Updated",
        last_name="Name",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.update_user.return_value = mock_detail

        client = TestClient(app)
        response = client.patch(
            f"/api/v1/users/{user_id}",
            json={"first_name": "Updated", "last_name": "Name"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "Name"


def test_update_user_role_as_admin(make_user_dict):
    """Test that promoting to admin requires super_admin (not just admin)."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.update_user.side_effect = ForbiddenError(
            message="Only super_admin can change admin roles",
            code="super_admin_role_change_denied",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.patch(
            f"/api/v1/users/{user_id}",
            json={"role": "admin"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 403
        assert "admin" in response.json()["detail"]


def test_update_user_role_to_super_admin_requires_super_admin(make_user_dict):
    """Test that promoting to super_admin requires super_admin."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.update_user.side_effect = ForbiddenError(
            message="Only super_admin can change to super_admin role",
            code="super_admin_role_change_denied",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.patch(
            f"/api/v1/users/{user_id}",
            json={"role": "super_admin"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 403
        assert "super_admin" in response.json()["detail"]


def test_delete_user(make_user_dict):
    """Test deleting a user."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/{user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 204
        mock_svc.delete_user.assert_called_once()


def test_delete_user_not_found(make_user_dict):
    """Test deleting a non-existent user."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    fake_id = "00000000-0000-0000-0000-000000000000"

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{fake_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 404


def test_delete_service_user_fails(make_user_dict):
    """Test that deleting a service user fails."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    service_user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.side_effect = ValidationError(
            message="Cannot delete service user",
            code="service_user_deletion",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{service_user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 400
        assert "service user" in response.json()["detail"].lower()


def test_delete_self_fails(make_user_dict):
    """Test that deleting yourself fails."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    admin_id = admin["id"]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.side_effect = ValidationError(
            message="Cannot delete your own account",
            code="self_deletion",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{admin_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 400
        assert "own account" in response.json()["detail"]


# =============================================================================
# User Email Management
# =============================================================================


def test_list_current_user_emails(make_user_dict):
    """Test listing current user's emails."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    # Return a list of EmailInfo (router wraps it in EmailList)
    mock_emails = [
        EmailInfo(
            id=str(uuid4()),
            email="primary@example.com",
            is_primary=True,
            verified_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
    ]

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.list_user_emails.return_value = mock_emails

        client = TestClient(app)
        response = client.get("/api/v1/users/me/emails")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) >= 1


def test_add_email_to_current_user(make_user_dict):
    """Test adding an email to current user's account."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    mock_email = EmailInfo(
        id=str(uuid4()),
        email="newemail@test.example.com",
        is_primary=False,
        verified_at=None,
        created_at=datetime.now(UTC),
    )

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with (
        patch("routers.api.v1.users.emails_service") as mock_svc,
        patch("routers.api.v1.users.send_email_verification"),
    ):
        mock_svc.add_user_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(
            "/api/v1/users/me/emails",
            json={"email": "newemail@test.example.com"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newemail@test.example.com"
        assert data["is_primary"] is False
        assert data["verified_at"] is None


def test_add_duplicate_email_fails(make_user_dict):
    """Test adding a duplicate email fails."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.add_user_email.side_effect = ConflictError(
            message="Email already exists", code="email_exists"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/users/me/emails",
            json={"email": "existing@example.com"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 409


def test_delete_email_from_current_user(make_user_dict):
    """Test deleting a secondary email from current user's account."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with (
        patch("routers.api.v1.users.emails_service") as mock_svc,
        patch("routers.api.v1.users.send_secondary_email_removed_notification"),
    ):
        mock_svc.delete_user_email.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/me/emails/{email_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 204


def test_cannot_delete_primary_email(make_user_dict):
    """Test that deleting primary email fails."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.delete_user_email.side_effect = ValidationError(
            message="Cannot delete primary email",
            code="primary_email_deletion",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/me/emails/{email_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 400
        assert "primary" in response.json()["detail"].lower()


def test_set_primary_email(make_user_dict):
    """Test setting a verified email as primary."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())

    mock_email = EmailInfo(
        id=email_id,
        email="newprimary@test.example.com",
        is_primary=True,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with (
        patch("routers.api.v1.users.emails_service") as mock_svc,
        patch("routers.api.v1.users.send_primary_email_changed_notification"),
    ):
        mock_svc.set_primary_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(f"/api/v1/users/me/emails/{email_id}/set-primary")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["is_primary"] is True


def test_cannot_set_unverified_email_as_primary(make_user_dict):
    """Test that setting an unverified email as primary fails."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.set_primary_email.side_effect = ValidationError(
            message="Cannot set unverified email as primary",
            code="unverified_email",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/me/emails/{email_id}/set-primary")

        app.dependency_overrides.clear()

        assert response.status_code == 400
        assert "unverified" in response.json()["detail"].lower()


def test_resend_email_verification(make_user_dict):
    """Test resending verification email."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())
    mock_email_data = {
        "email_id": email_id,
        "email": "resendtest@test.example.com",
        "verify_nonce": 12345,
    }

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with (
        patch("routers.api.v1.users.emails_service") as mock_svc,
        patch("routers.api.v1.users.send_email_verification"),
    ):
        mock_svc.resend_verification.return_value = mock_email_data

        client = TestClient(app)
        response = client.post(f"/api/v1/users/me/emails/{email_id}/resend-verification")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        assert "sent" in response.json()["message"].lower()


def test_verify_email(make_user_dict):
    """Test verifying an email address."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())

    mock_email = EmailInfo(
        id=email_id,
        email="verifytest@test.example.com",
        is_primary=False,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.verify_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/me/emails/{email_id}/verify",
            json={"nonce": 12345},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["verified_at"] is not None


def test_verify_email_invalid_nonce(make_user_dict):
    """Test verifying with invalid nonce fails."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]
    email_id = str(uuid4())

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.verify_email.side_effect = ValidationError(
            message="Invalid verification code",
            code="invalid_nonce",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            f"/api/v1/users/me/emails/{email_id}/verify",
            json={"nonce": 99999},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 400


# =============================================================================
# Admin Email Management
# =============================================================================


def test_admin_list_user_emails(make_user_dict):
    """Test admin listing a user's emails."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    mock_emails = [
        EmailInfo(
            id=str(uuid4()),
            email="user@example.com",
            is_primary=True,
            verified_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
    ]

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.list_user_emails.return_value = mock_emails

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/emails")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "items" in data


def test_admin_add_email_to_user(make_user_dict):
    """Test admin adding an email to a user (pre-verified)."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    mock_email = EmailInfo(
        id=str(uuid4()),
        email="adminadded@test.example.com",
        is_primary=False,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.add_user_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/{user_id}/emails",
            json={"email": "adminadded@test.example.com"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "adminadded@test.example.com"
        assert data["verified_at"] is not None


def test_admin_delete_user_email(make_user_dict):
    """Test admin deleting a user's secondary email."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())
    email_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.delete_user_email.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/{user_id}/emails/{email_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 204


def test_admin_set_user_primary_email(make_user_dict):
    """Test admin setting a user's primary email."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())
    email_id = str(uuid4())

    mock_email = EmailInfo(
        id=email_id,
        email="adminprimary@test.example.com",
        is_primary=True,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.set_primary_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/emails/{email_id}/set-primary")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["is_primary"] is True


# =============================================================================
# User MFA Management
# =============================================================================


def test_get_mfa_status(make_user_dict):
    """Test getting current user's MFA status."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    mock_status = MFAStatus(
        enabled=False,
        method=None,
        has_backup_codes=False,
    )

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.get_mfa_status.return_value = mock_status

        client = TestClient(app)
        response = client.get("/api/v1/users/me/mfa")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "enabled" in data
        assert "method" in data
        assert "has_backup_codes" in data


def test_setup_totp(make_user_dict):
    """Test initiating TOTP setup."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    mock_setup = TOTPSetupResponse(
        secret="TESTSECRET123456",
        uri="otpauth://totp/Test:user@example.com?secret=TESTSECRET123456&issuer=Test",
    )

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.setup_totp.return_value = mock_setup

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/totp/setup")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "uri" in data
        assert "otpauth://" in data["uri"]


def test_verify_totp_invalid_code(make_user_dict):
    """Test verifying TOTP with invalid code fails."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.verify_totp_and_enable.side_effect = ValidationError(
            message="Invalid TOTP code",
            code="invalid_totp",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/users/me/mfa/totp/verify",
            json={"code": "000000"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 400


def test_enable_email_mfa(make_user_dict):
    """Test enabling email MFA."""
    user = make_user_dict(role="member")
    tenant_id = user["tenant_id"]

    # Service returns tuple: (response, notification_info)
    # notification_info is None when MFA is enabled directly
    mock_response = MFAStatus(enabled=True, method="email", has_backup_codes=False)

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.enable_email_mfa.return_value = (mock_response, None)

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/email/enable")

        app.dependency_overrides.clear()

        assert response.status_code == 200


def test_disable_mfa(make_user_dict):
    """Test disabling MFA."""
    user = make_user_dict(role="member", mfa_enabled=True, mfa_method="email")
    tenant_id = user["tenant_id"]

    mock_status = MFAStatus(enabled=False, method=None, has_backup_codes=False)

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.disable_mfa.return_value = mock_status

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/disable")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False


def test_get_backup_codes_status(make_user_dict):
    """Test getting backup codes status."""
    user = make_user_dict(role="member", mfa_enabled=True)
    tenant_id = user["tenant_id"]

    mock_status = BackupCodesStatusResponse(total=5, used=0, remaining=5)

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.get_backup_codes_status.return_value = mock_status

        client = TestClient(app)
        response = client.get("/api/v1/users/me/mfa/backup-codes")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 5
        assert data["used"] == 0
        assert data["remaining"] == 5


def test_regenerate_backup_codes(make_user_dict):
    """Test regenerating backup codes."""
    user = make_user_dict(role="member", mfa_enabled=True, mfa_method="email")
    tenant_id = user["tenant_id"]

    mock_codes = BackupCodesResponse(
        codes=[
            "CODE1-CODE2",
            "CODE3-CODE4",
            "CODE5-CODE6",
            "CODE7-CODE8",
            "CODE9-CODE0",
            "CODEA-CODEB",
            "CODEC-CODED",
            "CODEE-CODEF",
            "CODEG-CODEH",
            "CODEI-CODEJ",
        ],
        count=10,
    )

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.regenerate_backup_codes.return_value = mock_codes

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/backup-codes/regenerate")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "codes" in data
        assert len(data["codes"]) == 10


def test_regenerate_backup_codes_requires_mfa(make_user_dict):
    """Test that regenerating backup codes requires MFA enabled."""
    user = make_user_dict(role="member", mfa_enabled=False)
    tenant_id = user["tenant_id"]

    app.dependency_overrides[get_current_user_api] = lambda: user
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.regenerate_backup_codes.side_effect = ValidationError(
            message="MFA must be enabled to regenerate backup codes",
            code="mfa_not_enabled",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/users/me/mfa/backup-codes/regenerate")

        app.dependency_overrides.clear()

        assert response.status_code == 400


# =============================================================================
# Admin MFA Management
# =============================================================================


def test_admin_reset_user_mfa(make_user_dict):
    """Test admin resetting a user's MFA."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    mock_status = MFAStatus(enabled=False, method=None, has_backup_codes=False)

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.return_value = mock_status

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/mfa/reset")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False


def test_reset_user_mfa_not_found_api(make_user_dict):
    """Test resetting MFA for non-existent user returns 404."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    fake_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{fake_id}/mfa/reset")

        app.dependency_overrides.clear()

        assert response.status_code == 404


def test_reset_user_mfa_forbidden_api(make_user_dict):
    """Test resetting MFA when service raises ForbiddenError returns 403."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.side_effect = ForbiddenError(
            message="Admin access required", code="admin_required"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{user_id}/mfa/reset")

        app.dependency_overrides.clear()

        assert response.status_code == 403


# =============================================================================
# User State Management (Inactivate/Reactivate/Anonymize)
# =============================================================================


def test_inactivate_user_as_admin(make_user_dict):
    """Test admin inactivating a user."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    mock_detail = UserDetail(
        id=user_id,
        email="user@example.com",
        first_name="Test",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
        is_inactivated=True,
        is_anonymized=False,
        inactivated_at=datetime.now(UTC),
        anonymized_at=None,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.inactivate_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/inactivate")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["is_inactivated"] is True
        assert data["inactivated_at"] is not None


# Note: test_inactivate_user_as_member_forbidden covered in integration tests


def test_inactivate_user_not_found(make_user_dict):
    """Test inactivating non-existent user returns 404."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    fake_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.inactivate_user.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{fake_id}/inactivate")

        app.dependency_overrides.clear()

        assert response.status_code == 404


def test_reactivate_user_as_admin(make_user_dict):
    """Test admin reactivating a user."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    mock_detail = UserDetail(
        id=user_id,
        email="user@example.com",
        first_name="Test",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.reactivate_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/reactivate")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["is_inactivated"] is False


def test_reactivate_user_not_inactivated(make_user_dict):
    """Test reactivating a user that isn't inactivated returns 400."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    user_id = str(uuid4())

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.reactivate_user.side_effect = ValidationError(
            message="User is not inactivated",
            code="not_inactivated",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{user_id}/reactivate")

        app.dependency_overrides.clear()

        assert response.status_code == 400
        assert "not inactivated" in response.json()["detail"]


# Note: test_reactivate_user_as_member_forbidden covered in integration tests


def test_anonymize_user_as_super_admin(make_user_dict):
    """Test super_admin anonymizing a user."""
    super_admin = make_user_dict(role="super_admin")
    tenant_id = super_admin["tenant_id"]
    user_id = str(uuid4())

    mock_detail = UserDetail(
        id=user_id,
        email=None,
        first_name="[Anonymized]",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
        is_inactivated=True,
        is_anonymized=True,
        inactivated_at=datetime.now(UTC),
        anonymized_at=datetime.now(UTC),
    )

    app.dependency_overrides[require_super_admin_api] = lambda: super_admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.anonymize_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/anonymize")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["is_anonymized"] is True
        assert data["anonymized_at"] is not None
        assert data["first_name"] == "[Anonymized]"


# Note: test_anonymize_user_as_admin_forbidden and test_anonymize_user_as_member_forbidden
# are covered in integration tests


# =============================================================================
# Password Status Field Tests
# =============================================================================


def test_get_user_includes_has_password_true(make_user_dict):
    """Test that GET /api/v1/users/{id} returns has_password=True for users with passwords."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    target_user_id = str(uuid4())

    mock_detail = UserDetail(
        id=target_user_id,
        email="user-with-password@example.com",
        first_name="Test",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[
            EmailInfo(
                id=str(uuid4()),
                email="user-with-password@example.com",
                is_primary=True,
                verified_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        ],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
        has_password=True,  # User has a password set
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "has_password" in data
        assert data["has_password"] is True


def test_get_user_includes_has_password_false(make_user_dict):
    """Test that GET /api/v1/users/{id} returns has_password=False for passwordless users."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    target_user_id = str(uuid4())

    mock_detail = UserDetail(
        id=target_user_id,
        email="jit-user@example.com",
        first_name="JIT",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[
            EmailInfo(
                id=str(uuid4()),
                email="jit-user@example.com",
                is_primary=True,
                verified_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        ],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
        has_password=False,  # JIT-provisioned user without password
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "has_password" in data
        assert data["has_password"] is False


def test_get_user_includes_saml_idp_info(make_user_dict):
    """Test that GET /api/v1/users/{id} returns SAML IdP assignment info."""
    admin = make_user_dict(role="admin")
    tenant_id = admin["tenant_id"]
    target_user_id = str(uuid4())
    idp_id = str(uuid4())

    mock_detail = UserDetail(
        id=target_user_id,
        email="saml-user@example.com",
        first_name="SAML",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[
            EmailInfo(
                id=str(uuid4()),
                email="saml-user@example.com",
                is_primary=True,
                verified_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        ],
        is_service_user=False,
        is_inactivated=False,
        is_anonymized=False,
        inactivated_at=None,
        anonymized_at=None,
        has_password=True,
        saml_idp_id=idp_id,
        saml_idp_name="Okta Corporate",
    )

    app.dependency_overrides[require_admin_api] = lambda: admin
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert "saml_idp_id" in data
        assert "saml_idp_name" in data
        assert data["saml_idp_id"] == idp_id
        assert data["saml_idp_name"] == "Okta Corporate"
        assert data["has_password"] is True  # Password preserved with IdP
