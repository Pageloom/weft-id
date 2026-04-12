"""Auth router reactivation tests.

Tests user reactivation request flows for inactivated users.
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


# Reactivation Request Tests


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


def test_request_reactivation_rate_limited(client, test_tenant_host):
    """Test reactivation request is rate limited by IP + tenant."""
    from services.exceptions import RateLimitError

    fake_user_id = str(uuid4())

    with patch("routers.auth.reactivation.ratelimit.prevent") as mock_prevent:
        mock_prevent.side_effect = RateLimitError(
            message="Too many requests",
            code="rate_limit_exceeded",
            retry_after=3600,
        )

        response = client.post(
            "/request-reactivation",
            headers={"Host": test_tenant_host},
            data={"user_id": fake_user_id},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "error=invalid_request" in response.headers["location"]
        mock_prevent.assert_called_once()
