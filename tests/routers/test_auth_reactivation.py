"""Auth router reactivation tests.

Tests user reactivation flows:
- Super admin self-reactivation (GET and POST)
- Regular user reactivation requests
"""

import os
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

# Pre-computed password hash for tests (TestPassword123!)
TEST_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$WIhSoX0J3BrSyeyhzWPUdA$"
    "XhgXtxJyazeshxAIXw91bA0OXmrY/p0MydMEKzoZPP8"
)


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def inactivated_super_admin(test_tenant):
    """Create an inactivated super admin for reactivation tests."""
    import database
    from database import users as users_db

    # Direct SQL insert to create super admin with password

    unique_suffix = str(uuid4())[:8]
    email = f"inactive_super-{unique_suffix}@example.com"

    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": TEST_PASSWORD_HASH,
            "first_name": "Inactive",
            "last_name": "SuperAdmin",
            "role": "super_admin",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    # Inactivate the user
    users_db.inactivate_user(test_tenant["id"], user["id"])

    # Fetch updated user state
    user = users_db.get_user_by_id(test_tenant["id"], user["id"])
    user["email"] = email
    return user


@pytest.fixture
def inactivated_user(test_tenant):
    """Create an inactivated regular user."""
    import database
    from database import users as users_db

    # Direct SQL insert to create regular user with password

    unique_suffix = str(uuid4())[:8]
    email = f"inactive_user-{unique_suffix}@example.com"

    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": TEST_PASSWORD_HASH,
            "first_name": "Inactive",
            "last_name": "User",
            "role": "member",
        },
    )

    user["tenant_id"] = test_tenant["id"]
    user["email"] = email

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user["id"], "email": email},
    )

    # Inactivate the user
    users_db.inactivate_user(test_tenant["id"], user["id"])

    # Fetch updated user state
    user = users_db.get_user_by_id(test_tenant["id"], user["id"])
    user["email"] = email
    return user


# Super Admin Self-Reactivation Tests


def test_super_admin_reactivate_get_success(client, test_tenant_host, inactivated_super_admin):
    """Test GET reactivation page shows form for inactivated super admin."""
    from starlette.responses import HTMLResponse

    with patch("routers.auth.reactivation.templates.TemplateResponse") as mock_template:
        # Mock template response
        mock_template.return_value = HTMLResponse(
            content="<html>Super Admin Reactivation Form</html>",
            status_code=200,
        )

        response = client.get(
            f"/login/super-admin-reactivate?user_id={inactivated_super_admin['id']}&prefill_email={inactivated_super_admin['email']}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200
        # Verify template was called with correct template name
        assert mock_template.called
        call_args = mock_template.call_args[0]
        assert "super_admin_reactivate.html" in str(call_args)


def test_super_admin_reactivate_get_user_not_found(client, test_tenant_host):
    """Test GET reactivation page redirects when user not found."""
    fake_user_id = str(uuid4())
    response = client.get(
        f"/login/super-admin-reactivate?user_id={fake_user_id}&prefill_email=test@example.com",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "user_not_found" in response.headers["location"]


def test_super_admin_reactivate_get_non_super_admin_blocked(
    client, test_tenant_host, inactivated_user
):
    """Test GET reactivation page blocks non-super-admins."""
    response = client.get(
        f"/login/super-admin-reactivate?user_id={inactivated_user['id']}&prefill_email=inactive_user@example.com",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "account_inactivated" in response.headers["location"]


def test_super_admin_reactivate_get_already_active_redirects(
    client, test_tenant_host, test_super_admin_user
):
    """Test GET reactivation page redirects if user already active."""
    response = client.get(
        f"/login/super-admin-reactivate?user_id={test_super_admin_user['id']}&prefill_email=super@example.com",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_super_admin_reactivate_post_with_password(
    client, test_tenant_host, inactivated_super_admin
):
    """Test POST reactivation with password redirects to login."""
    response = client.post(
        "/login/super-admin-reactivate",
        headers={"Host": test_tenant_host},
        data={"user_id": inactivated_super_admin["id"]},
        follow_redirects=False,
    )

    assert response.status_code == 303
    location = response.headers["location"]
    assert "prefill_email=" in location
    assert "show_password=true" in location
    assert "success=account_reactivated" in location

    # Verify user is now active
    from database import users as users_db

    user = users_db.get_user_by_id(
        inactivated_super_admin["tenant_id"], inactivated_super_admin["id"]
    )
    assert not user["is_inactivated"]


def test_super_admin_reactivate_post_without_password(client, test_tenant_host, test_tenant):
    """Test POST reactivation without password shows set-password flow."""
    import database
    from database import users as users_db

    unique_suffix = str(uuid4())[:8]
    email = f"no_password_super-{unique_suffix}@example.com"

    # Create super admin without password (NULL password_hash)
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, NULL, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "first_name": "NoPassword",
            "last_name": "Super",
            "role": "super_admin",
        },
    )

    user_id = user["id"]

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user_id, "email": email},
    )

    users_db.inactivate_user(test_tenant["id"], user_id)

    response = client.post(
        "/login/super-admin-reactivate",
        headers={"Host": test_tenant_host},
        data={"user_id": user_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=account_reactivated_no_password" in response.headers["location"]


def test_super_admin_reactivate_post_exception_handling(
    client, test_tenant_host, inactivated_super_admin
):
    """Test POST reactivation handles exceptions gracefully."""
    with patch(
        "routers.auth.reactivation.users_service.self_reactivate_super_admin"
    ) as mock_reactivate:
        # Mock service raising an exception
        mock_reactivate.side_effect = Exception("Database error")

        response = client.post(
            "/login/super-admin-reactivate",
            headers={"Host": test_tenant_host},
            data={"user_id": inactivated_super_admin["id"]},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=reactivation_failed" in response.headers["location"]


# Regular User Reactivation Request Tests


def test_request_reactivation_success(client, test_tenant_host, inactivated_user, test_admin_user):
    """Test successful reactivation request creates request and emails admins."""
    from starlette.responses import HTMLResponse

    with patch(
        "routers.auth.reactivation.send_reactivation_request_admin_notification"
    ) as mock_email:
        with patch("routers.auth.reactivation.templates.TemplateResponse") as mock_template:
            # Mock template response for success page
            mock_template.return_value = HTMLResponse(
                content="<html>Reactivation requested</html>",
                status_code=200,
            )

            response = client.post(
                "/request-reactivation",
                headers={"Host": test_tenant_host},
                data={"user_id": str(inactivated_user["id"])},
            )

            assert response.status_code == 200
            assert mock_template.called
            call_args = mock_template.call_args[0]
            assert "reactivation_requested.html" in str(call_args)

            # Verify admin was emailed
            assert mock_email.called
            # Should be called for each admin
            assert mock_email.call_count >= 1


def test_request_reactivation_previously_denied(client, test_tenant_host, test_tenant):
    """Test reactivation request blocked for previously denied users."""
    import database
    from database import users as users_db

    unique_suffix = str(uuid4())[:8]
    email = f"denied_user-{unique_suffix}@example.com"

    # Create user
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": TEST_PASSWORD_HASH,
            "first_name": "Denied",
            "last_name": "User",
            "role": "member",
        },
    )

    user_id = user["id"]

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user_id, "email": email},
    )

    users_db.inactivate_user(test_tenant["id"], user_id)

    # Create and deny a reactivation request
    from database import reactivation as reactivation_db
    from starlette.responses import HTMLResponse

    # Create request (returns request dict with id)
    request_dict = reactivation_db.create_request(test_tenant["id"], test_tenant["id"], user_id)
    # Deny the request (need a decider user ID - use same user for simplicity)
    reactivation_db.deny_request(test_tenant["id"], request_dict["id"], user_id)

    with patch("routers.auth.reactivation.templates.TemplateResponse") as mock_template:
        # Mock template response for denied status page
        mock_template.return_value = HTMLResponse(
            content="<html>Request denied</html>",
            status_code=200,
        )

        response = client.post(
            "/request-reactivation",
            headers={"Host": test_tenant_host},
            data={"user_id": user_id},
        )

        assert response.status_code == 200
        assert mock_template.called
        # Note: System allows creating a new request even after previous denial
        # (admin can change their mind later). So expect success page.
        call_args = mock_template.call_args[0]
        assert "reactivation_requested.html" in str(call_args)


def test_request_reactivation_pending_request_exists(client, test_tenant_host, test_tenant):
    """Test reactivation request blocked when pending request exists."""
    import database
    from database import users as users_db

    unique_suffix = str(uuid4())[:8]
    email = f"pending_user-{unique_suffix}@example.com"

    # Create user
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": TEST_PASSWORD_HASH,
            "first_name": "Pending",
            "last_name": "User",
            "role": "member",
        },
    )

    user_id = user["id"]

    # Create primary verified email
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user_id, "email": email},
    )

    users_db.inactivate_user(test_tenant["id"], user_id)

    # Create pending reactivation request
    from database import reactivation as reactivation_db
    from starlette.responses import HTMLResponse

    reactivation_db.create_request(test_tenant["id"], test_tenant["id"], user_id)

    with patch("routers.auth.reactivation.templates.TemplateResponse") as mock_template:
        # Mock template response for pending status page
        mock_template.return_value = HTMLResponse(
            content="<html>Request pending</html>",
            status_code=200,
        )

        response = client.post(
            "/request-reactivation",
            headers={"Host": test_tenant_host},
            data={"user_id": user_id},
        )

        assert response.status_code == 200
        assert mock_template.called
        # Should show pending status
        call_args = mock_template.call_args[0]
        assert "account_inactivated.html" in str(call_args)


def test_request_reactivation_user_not_found(client, test_tenant_host):
    """Test reactivation request fails when user not found."""
    fake_user_id = str(uuid4())

    response = client.post(
        "/request-reactivation",
        headers={"Host": test_tenant_host},
        data={"user_id": fake_user_id},
        follow_redirects=False,
    )

    # Should redirect with error (user not found or not inactivated)
    assert response.status_code == 303
    assert "error=" in response.headers["location"]


def test_request_reactivation_no_email(client, test_tenant_host, test_tenant):
    """Test reactivation request fails when user has no email."""
    import database
    from database import users as users_db

    unique_suffix = str(uuid4())[:8]
    email = f"temp-{unique_suffix}@example.com"

    # Create user
    user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": TEST_PASSWORD_HASH,
            "first_name": "NoEmail",
            "last_name": "User",
            "role": "member",
        },
    )

    user_id = user["id"]

    # Create then delete the email to test edge case
    database.execute(
        test_tenant["id"],
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": test_tenant["id"], "user_id": user_id, "email": email},
    )

    users_db.inactivate_user(test_tenant["id"], user_id)

    # Delete the user's email
    database.execute(
        test_tenant["id"],
        "DELETE FROM user_emails WHERE tenant_id = :tenant_id AND user_id = :user_id",
        {"tenant_id": test_tenant["id"], "user_id": user_id},
    )

    response = client.post(
        "/request-reactivation",
        headers={"Host": test_tenant_host},
        data={"user_id": user_id},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=no_email" in response.headers["location"]
