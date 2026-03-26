"""Unit tests for User Management API endpoints.

These tests use FastAPI dependency overrides and mocks to isolate the API layer.
For integration tests that use real services, see tests/integration/.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

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


def test_list_roles_as_admin(make_user_dict, override_api_auth):
    """Admin can list available roles."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_available_roles.return_value = ["member", "admin", "super_admin"]

        client = TestClient(app)
        response = client.get("/api/v1/users/roles")

        assert response.status_code == 200
        assert response.json() == ["member", "admin", "super_admin"]


# Note: Authorization tests (e.g., member cannot list roles) are better covered
# in integration tests where the full auth flow is tested. Unit tests focus on
# testing the business logic when auth is satisfied.
# =============================================================================
# User List
# =============================================================================


def test_list_users_as_admin(make_user_dict, override_api_auth):
    """Test listing users as admin."""
    admin = make_user_dict(role="admin")

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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/users")

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert data["page"] == 1
        assert data["limit"] == 25
        assert data["total"] == 1


def test_list_users_with_pagination(make_user_dict, override_api_auth):
    """Test listing users with pagination parameters."""
    admin = make_user_dict(role="admin")

    mock_response = UserListResponse(items=[], total=0, page=1, limit=5)

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/users?page=1&limit=5")

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["limit"] == 5


def test_list_users_with_filters(make_user_dict, override_api_auth):
    """Test listing users with role, status, and auth_method filters."""
    admin = make_user_dict(role="admin")

    mock_response = UserListResponse(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get(
            "/api/v1/users?role=admin,member&status=active&auth_method=password_email"
        )

        assert response.status_code == 200
        call_kwargs = mock_svc.list_users.call_args
        # Verify filter params were parsed and passed
        assert call_kwargs.kwargs.get("roles") == ["admin", "member"]
        assert call_kwargs.kwargs.get("statuses") == ["active"]
        assert call_kwargs.kwargs.get("auth_methods") == ["password_email"]


# Note: test_list_users_unauthorized is covered in integration tests


def test_get_user_as_admin(make_user_dict, override_api_auth):
    """Test getting a user's details as admin."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == target_user_id
        assert data["first_name"] == "Target"
        assert data["last_name"] == "User"
        assert "emails" in data
        assert "is_service_user" in data


def test_get_user_not_found(make_user_dict, override_api_auth):
    """Test getting a non-existent user."""
    admin = make_user_dict(role="admin")
    fake_id = "00000000-0000-0000-0000-000000000000"

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(f"/api/v1/users/{fake_id}")

        assert response.status_code == 404


def test_create_user_as_admin(make_user_dict, override_api_auth):
    """Test creating a new user as admin."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

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

        assert response.status_code == 201
        data = response.json()
        assert data["first_name"] == "New"
        assert data["last_name"] == "User"
        assert data["role"] == "member"
        assert len(data["emails"]) == 1
        assert data["emails"][0]["email"] == "newuser@test.example.com"
        assert data["emails"][0]["is_primary"] is True


def test_create_user_duplicate_email(make_user_dict, override_api_auth):
    """Test creating a user with duplicate email."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

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

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]


def test_create_user_as_super_admin_with_super_admin_role(make_user_dict, override_api_auth):
    """Test that super_admin can create users with super_admin role."""
    super_admin = make_user_dict(role="super_admin")
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

    override_api_auth(super_admin)

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

        assert response.status_code == 201
        data = response.json()
        assert data["role"] == "super_admin"


def test_create_user_admin_cannot_create_super_admin(make_user_dict, override_api_auth):
    """Test that regular admin cannot create users with super_admin role."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

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

        assert response.status_code == 403
        assert "Only super_admin" in response.json()["detail"]


def test_update_user_name(make_user_dict, override_api_auth):
    """Test updating a user's name."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.update_user.return_value = mock_detail

        client = TestClient(app)
        response = client.patch(
            f"/api/v1/users/{user_id}",
            json={"first_name": "Updated", "last_name": "Name"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Updated"
        assert data["last_name"] == "Name"


def test_update_user_role_as_admin(make_user_dict, override_api_auth):
    """Test that promoting to admin requires super_admin (not just admin)."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

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

        assert response.status_code == 403
        assert "admin" in response.json()["detail"]


def test_update_user_role_to_super_admin_requires_super_admin(make_user_dict, override_api_auth):
    """Test that promoting to super_admin requires super_admin."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

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

        assert response.status_code == 403
        assert "super_admin" in response.json()["detail"]


def test_delete_user(make_user_dict, override_api_auth):
    """Test deleting a user."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/{user_id}")

        assert response.status_code == 204
        mock_svc.delete_user.assert_called_once()


def test_delete_user_not_found(make_user_dict, override_api_auth):
    """Test deleting a non-existent user."""
    admin = make_user_dict(role="admin")
    fake_id = "00000000-0000-0000-0000-000000000000"

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{fake_id}")

        assert response.status_code == 404


def test_delete_service_user_fails(make_user_dict, override_api_auth):
    """Test that deleting a service user fails."""
    admin = make_user_dict(role="admin")
    service_user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.side_effect = ValidationError(
            message="Cannot delete service user",
            code="service_user_deletion",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{service_user_id}")

        assert response.status_code == 400
        assert "service user" in response.json()["detail"].lower()


def test_delete_self_fails(make_user_dict, override_api_auth):
    """Test that deleting yourself fails."""
    admin = make_user_dict(role="admin")
    admin_id = admin["id"]

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.delete_user.side_effect = ValidationError(
            message="Cannot delete your own account",
            code="self_deletion",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{admin_id}")

        assert response.status_code == 400
        assert "own account" in response.json()["detail"]


# =============================================================================
# User Email Management
# =============================================================================


def test_list_current_user_emails(make_user_dict, override_api_auth):
    """Test listing current user's emails."""
    user = make_user_dict(role="member")

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

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.list_user_emails.return_value = mock_emails

        client = TestClient(app)
        response = client.get("/api/v1/users/me/emails")

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert len(data["items"]) >= 1


# =============================================================================
# Admin Email Management
# =============================================================================


def test_admin_list_user_emails(make_user_dict, override_api_auth):
    """Test admin listing a user's emails."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.list_user_emails.return_value = mock_emails

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/emails")

        assert response.status_code == 200
        data = response.json()
        assert "items" in data


def test_admin_add_email_to_user(make_user_dict, override_api_auth):
    """Test admin adding an email to a user (pre-verified)."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    mock_email = EmailInfo(
        id=str(uuid4()),
        email="adminadded@test.example.com",
        is_primary=False,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.add_user_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/{user_id}/emails",
            json={"email": "adminadded@test.example.com"},
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "adminadded@test.example.com"
        assert data["verified_at"] is not None


def test_admin_delete_user_email(make_user_dict, override_api_auth):
    """Test admin deleting a user's secondary email."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    email_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.delete_user_email.return_value = None

        client = TestClient(app)
        response = client.delete(f"/api/v1/users/{user_id}/emails/{email_id}")

        assert response.status_code == 204


def test_admin_set_user_primary_email(make_user_dict, override_api_auth):
    """Test admin setting a user's primary email."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    email_id = str(uuid4())

    mock_email = EmailInfo(
        id=email_id,
        email="adminprimary@test.example.com",
        is_primary=True,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.get_email_address_by_id.return_value = "adminprimary@test.example.com"
        mock_svc.check_routing_change.return_value = None
        mock_svc.set_primary_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/emails/{email_id}/set-primary")

        assert response.status_code == 200
        data = response.json()
        assert data["is_primary"] is True


def test_admin_set_primary_email_routing_change_blocked(make_user_dict, override_api_auth):
    """Test admin promote returns 409 when IdP routing would change."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    email_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.get_email_address_by_id.return_value = "user@other-idp.com"
        mock_svc.check_routing_change.return_value = {
            "current_idp_name": "Okta Corporate",
            "new_idp_name": "Google Workspace",
        }

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{user_id}/emails/{email_id}/set-primary")

        assert response.status_code == 409
        data = response.json()["detail"]
        assert data["error_code"] == "routing_change"
        assert data["details"]["current_idp_name"] == "Okta Corporate"
        assert data["details"]["new_idp_name"] == "Google Workspace"


def test_admin_set_primary_email_routing_change_confirmed(make_user_dict, override_api_auth):
    """Test admin promote succeeds when routing change is confirmed."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    email_id = str(uuid4())

    mock_email = EmailInfo(
        id=email_id,
        email="user@other-idp.com",
        is_primary=True,
        verified_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.set_primary_email.return_value = mock_email

        client = TestClient(app)
        response = client.post(
            f"/api/v1/users/{user_id}/emails/{email_id}/set-primary?confirm_routing_change=true"
        )

        assert response.status_code == 200
        # Should not check routing when confirm_routing_change=true
        mock_svc.check_routing_change.assert_not_called()


# =============================================================================
# Admin Email Management - Error Paths
# =============================================================================


def test_list_current_user_emails_service_error(make_user_dict, override_api_auth):
    """Test listing current user emails returns error on ServiceError."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.list_user_emails.side_effect = ForbiddenError(
            message="Forbidden", code="forbidden"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/v1/users/me/emails")

        assert response.status_code == 403


def test_admin_list_user_emails_service_error(make_user_dict, override_api_auth):
    """Test admin listing emails returns error on ServiceError."""
    admin = make_user_dict(role="admin")
    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.list_user_emails.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(f"/api/v1/users/{uuid4()}/emails")

        assert response.status_code == 404


def test_admin_add_email_service_error(make_user_dict, override_api_auth):
    """Test admin add email returns error on ServiceError."""
    admin = make_user_dict(role="admin")
    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.add_user_email.side_effect = ValidationError(
            message="Domain not privileged", code="domain_not_privileged"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            f"/api/v1/users/{uuid4()}/emails",
            json={"email": "bad@external.com"},
        )

        assert response.status_code == 400


def test_admin_delete_email_service_error(make_user_dict, override_api_auth):
    """Test admin delete email returns error on ServiceError."""
    admin = make_user_dict(role="admin")
    override_api_auth(admin)

    with patch("routers.api.v1.users.emails_service") as mock_svc:
        mock_svc.delete_user_email.side_effect = ValidationError(
            message="Cannot remove primary", code="cannot_remove_primary"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.delete(f"/api/v1/users/{uuid4()}/emails/{uuid4()}")

        assert response.status_code == 400


# =============================================================================
# User MFA Management
# =============================================================================


def test_get_mfa_status(make_user_dict, override_api_auth):
    """Test getting current user's MFA status."""
    user = make_user_dict(role="member")

    mock_status = MFAStatus(
        enabled=False,
        method=None,
        has_backup_codes=False,
    )

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.get_mfa_status.return_value = mock_status

        client = TestClient(app)
        response = client.get("/api/v1/users/me/mfa")

        assert response.status_code == 200
        data = response.json()
        assert "enabled" in data
        assert "method" in data
        assert "has_backup_codes" in data


def test_setup_totp(make_user_dict, override_api_auth):
    """Test initiating TOTP setup."""
    user = make_user_dict(role="member")

    mock_setup = TOTPSetupResponse(
        secret="TESTSECRET123456",
        uri="otpauth://totp/Test:user@example.com?secret=TESTSECRET123456&issuer=Test",
    )

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.setup_totp.return_value = mock_setup

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/totp/setup")

        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert "uri" in data
        assert "otpauth://" in data["uri"]


def test_verify_totp_invalid_code(make_user_dict, override_api_auth):
    """Test verifying TOTP with invalid code fails."""
    user = make_user_dict(role="member")

    override_api_auth(user, level="user")

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

        assert response.status_code == 400


def test_enable_email_mfa(make_user_dict, override_api_auth):
    """Test enabling email MFA."""
    user = make_user_dict(role="member")

    # Service returns tuple: (response, notification_info)
    # notification_info is None when MFA is enabled directly
    mock_response = MFAStatus(enabled=True, method="email", has_backup_codes=False)

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.enable_email_mfa.return_value = (mock_response, None)

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/email/enable")

        assert response.status_code == 200


def test_disable_mfa(make_user_dict, override_api_auth):
    """Test disabling MFA."""
    user = make_user_dict(role="member", mfa_enabled=True, mfa_method="email")

    mock_status = MFAStatus(enabled=False, method=None, has_backup_codes=False)

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.disable_mfa.return_value = mock_status

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/disable")

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False


def test_get_backup_codes_status(make_user_dict, override_api_auth):
    """Test getting backup codes status."""
    user = make_user_dict(role="member", mfa_enabled=True)

    mock_status = BackupCodesStatusResponse(total=5, used=0, remaining=5)

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.get_backup_codes_status.return_value = mock_status

        client = TestClient(app)
        response = client.get("/api/v1/users/me/mfa/backup-codes")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 5
        assert data["used"] == 0
        assert data["remaining"] == 5


def test_regenerate_backup_codes(make_user_dict, override_api_auth):
    """Test regenerating backup codes."""
    user = make_user_dict(role="member", mfa_enabled=True, mfa_method="email")

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

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.regenerate_backup_codes.return_value = mock_codes

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/backup-codes/regenerate")

        assert response.status_code == 200
        data = response.json()
        assert "codes" in data
        assert len(data["codes"]) == 10


def test_regenerate_backup_codes_requires_mfa(make_user_dict, override_api_auth):
    """Test that regenerating backup codes requires MFA enabled."""
    user = make_user_dict(role="member", mfa_enabled=False)

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.regenerate_backup_codes.side_effect = ValidationError(
            message="MFA must be enabled to regenerate backup codes",
            code="mfa_not_enabled",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/users/me/mfa/backup-codes/regenerate")

        assert response.status_code == 400


# =============================================================================
# Admin MFA Management
# =============================================================================


def test_admin_reset_user_mfa(make_user_dict, override_api_auth):
    """Test admin resetting a user's MFA."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    mock_status = MFAStatus(enabled=False, method=None, has_backup_codes=False)

    override_api_auth(admin)

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.return_value = mock_status

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/mfa/reset")

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False


def test_reset_user_mfa_not_found_api(make_user_dict, override_api_auth):
    """Test resetting MFA for non-existent user returns 404."""
    admin = make_user_dict(role="admin")
    fake_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{fake_id}/mfa/reset")

        assert response.status_code == 404


def test_reset_user_mfa_forbidden_api(make_user_dict, override_api_auth):
    """Test resetting MFA when service raises ForbiddenError returns 403."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.side_effect = ForbiddenError(
            message="Admin access required", code="admin_required"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{user_id}/mfa/reset")

        assert response.status_code == 403


# =============================================================================
# User State Management (Inactivate/Reactivate/Anonymize)
# =============================================================================


def test_inactivate_user_as_admin(make_user_dict, override_api_auth):
    """Test admin inactivating a user."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.inactivate_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/inactivate")

        assert response.status_code == 200
        data = response.json()
        assert data["is_inactivated"] is True
        assert data["inactivated_at"] is not None


# Note: test_inactivate_user_as_member_forbidden covered in integration tests


def test_inactivate_user_not_found(make_user_dict, override_api_auth):
    """Test inactivating non-existent user returns 404."""
    admin = make_user_dict(role="admin")
    fake_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.inactivate_user.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{fake_id}/inactivate")

        assert response.status_code == 404


def test_reactivate_user_as_admin(make_user_dict, override_api_auth):
    """Test admin reactivating a user."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.reactivate_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/reactivate")

        assert response.status_code == 200
        data = response.json()
        assert data["is_inactivated"] is False


def test_reactivate_user_not_inactivated(make_user_dict, override_api_auth):
    """Test reactivating a user that isn't inactivated returns 400."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.reactivate_user.side_effect = ValidationError(
            message="User is not inactivated",
            code="not_inactivated",
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{user_id}/reactivate")

        assert response.status_code == 400
        assert "not inactivated" in response.json()["detail"]


# Note: test_reactivate_user_as_member_forbidden covered in integration tests


def test_anonymize_user_as_super_admin(make_user_dict, override_api_auth):
    """Test super_admin anonymizing a user."""
    super_admin = make_user_dict(role="super_admin")
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

    override_api_auth(super_admin, level="super_admin")

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.anonymize_user.return_value = mock_detail

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{user_id}/anonymize")

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


def test_get_user_includes_has_password_true(make_user_dict, override_api_auth):
    """Test that GET /api/v1/users/{id} returns has_password=True for users with passwords."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        assert response.status_code == 200
        data = response.json()
        assert "has_password" in data
        assert data["has_password"] is True


def test_get_user_includes_has_password_false(make_user_dict, override_api_auth):
    """Test that GET /api/v1/users/{id} returns has_password=False for passwordless users."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        assert response.status_code == 200
        data = response.json()
        assert "has_password" in data
        assert data["has_password"] is False


def test_get_user_includes_saml_idp_info(make_user_dict, override_api_auth):
    """Test that GET /api/v1/users/{id} returns SAML IdP assignment info."""
    admin = make_user_dict(role="admin")
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

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.get_user.return_value = mock_detail

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{target_user_id}")

        assert response.status_code == 200
        data = response.json()
        assert "saml_idp_id" in data
        assert "saml_idp_name" in data
        assert data["saml_idp_id"] == idp_id
        assert data["saml_idp_name"] == "Okta Corporate"
        assert data["has_password"] is True  # Password preserved with IdP


# =============================================================================
# User IdP Assignment
# =============================================================================


def test_assign_user_idp_as_super_admin(make_user_dict, override_api_auth):
    """Super admin can assign a user to an IdP."""
    super_admin = make_user_dict(role="super_admin")
    target_user_id = str(uuid4())
    idp_id = str(uuid4())

    override_api_auth(super_admin, level="super_admin")

    with patch("routers.api.v1.users.saml_service") as mock_svc:
        client = TestClient(app)
        response = client.put(
            f"/api/v1/users/{target_user_id}/idp",
            json={"saml_idp_id": idp_id},
        )

        assert response.status_code == 204
        mock_svc.assign_user_idp.assert_called_once()
        call_kwargs = mock_svc.assign_user_idp.call_args
        assert call_kwargs.kwargs["user_id"] == target_user_id
        assert call_kwargs.kwargs["saml_idp_id"] == idp_id


def test_assign_user_idp_set_password_only(make_user_dict, override_api_auth):
    """Super admin can set a user as password-only by passing null."""
    super_admin = make_user_dict(role="super_admin")
    target_user_id = str(uuid4())

    override_api_auth(super_admin, level="super_admin")

    with patch("routers.api.v1.users.saml_service") as mock_svc:
        client = TestClient(app)
        response = client.put(
            f"/api/v1/users/{target_user_id}/idp",
            json={"saml_idp_id": None},
        )

        assert response.status_code == 204
        call_kwargs = mock_svc.assign_user_idp.call_args
        assert call_kwargs.kwargs["saml_idp_id"] is None


def test_assign_user_idp_not_found(make_user_dict, override_api_auth):
    """Returns 404 when user or IdP not found."""
    super_admin = make_user_dict(role="super_admin")
    target_user_id = str(uuid4())

    override_api_auth(super_admin, level="super_admin")

    with patch("routers.api.v1.users.saml_service") as mock_svc:
        mock_svc.assign_user_idp.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.put(
            f"/api/v1/users/{target_user_id}/idp",
            json={"saml_idp_id": str(uuid4())},
        )

        assert response.status_code == 404


def test_assign_user_idp_validation_error(make_user_dict, override_api_auth):
    """Returns 400 on validation error (e.g., already assigned to same IdP)."""
    super_admin = make_user_dict(role="super_admin")
    target_user_id = str(uuid4())

    override_api_auth(super_admin, level="super_admin")

    with patch("routers.api.v1.users.saml_service") as mock_svc:
        mock_svc.assign_user_idp.side_effect = ValidationError(
            message="User already assigned to this IdP", code="already_assigned"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.put(
            f"/api/v1/users/{target_user_id}/idp",
            json={"saml_idp_id": str(uuid4())},
        )

        assert response.status_code == 400


def test_assign_user_idp_forbidden_error(make_user_dict, override_api_auth):
    """Returns 403 when service raises ForbiddenError."""
    super_admin = make_user_dict(role="super_admin")
    target_user_id = str(uuid4())

    override_api_auth(super_admin, level="super_admin")

    with patch("routers.api.v1.users.saml_service") as mock_svc:
        mock_svc.assign_user_idp.side_effect = ForbiddenError(
            message="Insufficient permissions", code="forbidden"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.put(
            f"/api/v1/users/{target_user_id}/idp",
            json={"saml_idp_id": str(uuid4())},
        )

        assert response.status_code == 403


# Note: test_assign_user_idp_admin_forbidden (role-based auth) is covered
# in integration tests where the full auth flow is tested.


# =============================================================================
# User Accessible Apps
# =============================================================================


def test_get_user_accessible_apps_as_admin(make_user_dict, override_api_auth):
    """Admin can get accessible apps for a user."""
    from schemas.service_providers import (
        GrantingGroup,
        UserAccessibleApp,
        UserAccessibleAppList,
    )

    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    sp_id = str(uuid4())
    group_id = str(uuid4())

    mock_result = UserAccessibleAppList(
        items=[
            UserAccessibleApp(
                id=sp_id,
                name="Test App",
                description="A test application",
                entity_id="https://app.example.com",
                available_to_all=False,
                granting_groups=[
                    GrantingGroup(id=group_id, name="Engineering"),
                ],
            ),
        ],
        total=1,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.users.sp_service") as mock_svc:
        mock_svc.get_user_accessible_apps_admin.return_value = mock_result

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/accessible-apps")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["id"] == sp_id
        assert data["items"][0]["name"] == "Test App"
        assert data["items"][0]["available_to_all"] is False
        assert len(data["items"][0]["granting_groups"]) == 1
        assert data["items"][0]["granting_groups"][0]["name"] == "Engineering"


def test_get_user_accessible_apps_empty(make_user_dict, override_api_auth):
    """Returns empty list when user has no accessible apps."""
    from schemas.service_providers import UserAccessibleAppList

    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.sp_service") as mock_svc:
        mock_svc.get_user_accessible_apps_admin.return_value = UserAccessibleAppList(
            items=[], total=0
        )

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/accessible-apps")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []


def test_get_user_accessible_apps_user_not_found(make_user_dict, override_api_auth):
    """Returns 404 when target user does not exist."""
    admin = make_user_dict(role="admin")
    fake_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.sp_service") as mock_svc:
        mock_svc.get_user_accessible_apps_admin.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(f"/api/v1/users/{fake_id}/accessible-apps")

        assert response.status_code == 404


def test_get_user_accessible_apps_forbidden(make_user_dict, override_api_auth):
    """Returns 403 when service raises ForbiddenError."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.sp_service") as mock_svc:
        mock_svc.get_user_accessible_apps_admin.side_effect = ForbiddenError(
            message="Admin access required", code="admin_required"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get(f"/api/v1/users/{user_id}/accessible-apps")

        assert response.status_code == 403


def test_get_user_accessible_apps_available_to_all(make_user_dict, override_api_auth):
    """Available-to-all apps are returned with empty granting_groups."""
    from schemas.service_providers import UserAccessibleApp, UserAccessibleAppList

    admin = make_user_dict(role="admin")
    user_id = str(uuid4())
    sp_id = str(uuid4())

    mock_result = UserAccessibleAppList(
        items=[
            UserAccessibleApp(
                id=sp_id,
                name="Public App",
                description=None,
                entity_id="https://public.example.com",
                available_to_all=True,
                granting_groups=[],
            ),
        ],
        total=1,
    )

    override_api_auth(admin)

    with patch("routers.api.v1.users.sp_service") as mock_svc:
        mock_svc.get_user_accessible_apps_admin.return_value = mock_result

        client = TestClient(app)
        response = client.get(f"/api/v1/users/{user_id}/accessible-apps")

        assert response.status_code == 200
        data = response.json()
        assert data["items"][0]["available_to_all"] is True
        assert data["items"][0]["granting_groups"] == []


# =============================================================================
# User List Filter Edge Cases
# =============================================================================


def test_list_users_with_invalid_role_filter(make_user_dict, override_api_auth):
    """Invalid role values are silently dropped, resulting in no filter."""
    admin = make_user_dict(role="admin")
    mock_response = UserListResponse(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/users?role=bogus_role")

        assert response.status_code == 200
        call_kwargs = mock_svc.list_users.call_args[1]
        assert call_kwargs["roles"] is None


def test_list_users_with_invalid_status_filter(make_user_dict, override_api_auth):
    """Invalid status values are silently dropped, resulting in no filter."""
    admin = make_user_dict(role="admin")
    mock_response = UserListResponse(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        response = client.get("/api/v1/users?status=bogus_status")

        assert response.status_code == 200
        call_kwargs = mock_svc.list_users.call_args[1]
        assert call_kwargs["statuses"] is None


def test_list_users_with_empty_auth_method_filter(make_user_dict, override_api_auth):
    """Empty auth_method values are silently dropped, resulting in no filter."""
    admin = make_user_dict(role="admin")
    mock_response = UserListResponse(items=[], total=0, page=1, limit=25)

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.return_value = mock_response

        client = TestClient(app)
        # Comma-only string produces empty items after strip
        response = client.get("/api/v1/users?auth_method=,,,")

        assert response.status_code == 200
        call_kwargs = mock_svc.list_users.call_args[1]
        assert call_kwargs["auth_methods"] is None


def test_list_users_service_error(make_user_dict, override_api_auth):
    """Service error on list returns HTTP error."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.list_users.side_effect = ForbiddenError(message="Not allowed", code="forbidden")

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/v1/users")

        assert response.status_code == 403


# =============================================================================
# User Profile Update
# =============================================================================


def test_update_current_user_profile_success(make_user_dict, override_api_auth):
    """User can update their own profile."""
    from schemas.api import UserProfile

    user = make_user_dict(role="member")

    override_api_auth(user, level="user")

    mock_profile = UserProfile(
        id=user["id"],
        email=user["email"],
        first_name="Updated",
        last_name="Name",
        role="member",
        timezone="America/New_York",
        locale="en_US",
        theme="dark",
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
    )

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.update_current_user_profile.return_value = mock_profile

        client = TestClient(app)
        response = client.patch(
            "/api/v1/users/me",
            json={"first_name": "Updated", "timezone": "America/New_York"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["first_name"] == "Updated"
        assert data["timezone"] == "America/New_York"


def test_update_current_user_profile_service_error(make_user_dict, override_api_auth):
    """Service error on profile update returns HTTP error."""
    user = make_user_dict(role="member")

    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.update_current_user_profile.side_effect = ValidationError(
            message="Invalid timezone", code="invalid_timezone"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.patch(
            "/api/v1/users/me",
            json={"timezone": "Invalid/Timezone"},
        )

        assert response.status_code == 400
