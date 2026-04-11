"""Tests for routers/auth/password_reset.py endpoints."""

from uuid import uuid4

from dependencies import get_tenant_id_from_request
from fastapi.testclient import TestClient
from main import app

AUTH_PW_RESET = "routers.auth.password_reset"

TENANT_ID = str(uuid4())


def _setup(mocker):
    """Common setup: override tenant dependency and patch at module level."""
    app.dependency_overrides[get_tenant_id_from_request] = lambda: TENANT_ID
    mocker.patch(f"{AUTH_PW_RESET}.get_tenant_id_from_request", return_value=TENANT_ID)


class TestForgotPassword:
    """Tests for /forgot-password endpoints."""

    def teardown_method(self):
        app.dependency_overrides.clear()

    def test_get_renders_form(self, mocker):
        _setup(mocker)
        client = TestClient(app)
        response = client.get("/forgot-password")
        assert response.status_code == 200
        assert "Forgot Password" in response.text

    def test_post_redirects_success(self, mocker):
        _setup(mocker)
        mocker.patch(f"{AUTH_PW_RESET}.ratelimit")
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/forgot-password",
            data={"email": "user@example.com", "csrf_token": "test"},
        )

        assert response.status_code == 303
        assert "/forgot-password?success=email_sent" in response.headers["location"]
        mock_svc.request_password_reset.assert_called_once()

    def test_post_same_response_unknown_email(self, mocker):
        _setup(mocker)
        mocker.patch(f"{AUTH_PW_RESET}.ratelimit")
        mocker.patch(f"{AUTH_PW_RESET}.users_service")

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/forgot-password",
            data={"email": "nobody@example.com", "csrf_token": "test"},
        )

        assert response.status_code == 303
        assert "/forgot-password?success=email_sent" in response.headers["location"]

    def test_post_rate_limited_still_shows_success(self, mocker):
        from services.exceptions import RateLimitError

        _setup(mocker)
        mock_rl = mocker.patch(f"{AUTH_PW_RESET}.ratelimit")
        mock_rl.prevent.side_effect = RateLimitError(
            message="Too many requests", code="rate_limited"
        )

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/forgot-password",
            data={"email": "user@example.com", "csrf_token": "test"},
        )

        assert response.status_code == 303
        assert "/forgot-password?success=email_sent" in response.headers["location"]


class TestResetPassword:
    """Tests for /reset-password/{token} endpoints."""

    def teardown_method(self):
        app.dependency_overrides.clear()

    def test_get_valid_token(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_reset_token.return_value = {
            "user_id": user_id,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app)
        response = client.get("/reset-password/valid-token")

        assert response.status_code == 200
        assert "Set New Password" in response.text

    def test_get_invalid_token(self, mocker):
        _setup(mocker)
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_reset_token.return_value = None

        client = TestClient(app, follow_redirects=False)
        response = client.get("/reset-password/bad-token")

        assert response.status_code == 303
        assert "/forgot-password?error=invalid_or_expired" in response.headers["location"]

    def test_post_success(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_reset_token.return_value = {
            "user_id": user_id,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/reset-password/valid-token",
            data={
                "new_password": "new_strong_password",
                "new_password_confirm": "new_strong_password",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 303
        assert "/login?success=password_reset" in response.headers["location"]
        mock_svc.complete_self_service_password_reset.assert_called_once_with(
            TENANT_ID, user_id, "new_strong_password"
        )

    def test_post_password_mismatch(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_reset_token.return_value = {
            "user_id": user_id,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app)
        response = client.post(
            "/reset-password/valid-token",
            data={
                "new_password": "password_one",
                "new_password_confirm": "password_two",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 200
        assert "Passwords do not match" in response.text

    def test_post_weak_password(self, mocker):
        from services.exceptions import ValidationError

        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_reset_token.return_value = {
            "user_id": user_id,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }
        mock_svc.complete_self_service_password_reset.side_effect = ValidationError(
            message="Too weak", code="password_too_weak"
        )

        client = TestClient(app)
        response = client.post(
            "/reset-password/valid-token",
            data={
                "new_password": "weak",
                "new_password_confirm": "weak",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 200
        assert "not strong enough" in response.text

    def test_post_invalid_token(self, mocker):
        _setup(mocker)
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_reset_token.return_value = None

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/reset-password/bad-token",
            data={
                "new_password": "new_password",
                "new_password_confirm": "new_password",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 303
        assert "/forgot-password?error=invalid_or_expired" in response.headers["location"]


class TestLoginForgotPasswordLink:
    """Test that the login page includes the forgot password link."""

    def teardown_method(self):
        app.dependency_overrides.clear()

    def test_login_page_shows_forgot_password_link(self, mocker):
        app.dependency_overrides[get_tenant_id_from_request] = lambda: TENANT_ID
        mocker.patch("routers.auth.login.get_current_user", return_value=None)
        mocker.patch("routers.auth.login.get_tenant_id_from_request", return_value=TENANT_ID)

        client = TestClient(app)
        response = client.get("/login?show_password=true&prefill_email=test@example.com")

        assert response.status_code == 200
        assert "Forgot password?" in response.text
        assert "/forgot-password" in response.text


class TestAccountRecovery:
    """Tests for /account-recovery/{token} endpoints."""

    def teardown_method(self):
        app.dependency_overrides.clear()

    def test_get_active_password_user_shows_reset_form(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = {
            "user_id": user_id,
            "is_inactivated": False,
            "has_password": True,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app)
        response = client.get("/account-recovery/valid-token")

        assert response.status_code == 200
        assert "Set New Password" in response.text
        # Form action should point to account-recovery (recovery mode)
        assert "/account-recovery/valid-token" in response.text

    def test_get_inactivated_user_shows_disclosure(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = {
            "user_id": user_id,
            "is_inactivated": True,
            "has_password": False,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app)
        response = client.get("/account-recovery/valid-token")

        assert response.status_code == 200
        assert "Account Inactivated" in response.text
        assert "Request Reactivation" in response.text

    def test_get_inactivated_super_admin_shows_reactivation_request(self, mocker):
        """Inactivated super admins see the same request form as regular users."""
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = {
            "user_id": user_id,
            "is_inactivated": True,
            "has_password": True,
            "role": "super_admin",
            "minimum_password_length": 20,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app)
        response = client.get("/account-recovery/valid-token")

        assert response.status_code == 200
        assert "Account Inactivated" in response.text
        assert "Request Reactivation" in response.text

    def test_get_invalid_token(self, mocker):
        _setup(mocker)
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = None

        client = TestClient(app, follow_redirects=False)
        response = client.get("/account-recovery/bad-token")

        assert response.status_code == 303
        assert "/forgot-password?error=invalid_or_expired" in response.headers["location"]

    def test_post_password_reset_success(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = {
            "user_id": user_id,
            "is_inactivated": False,
            "has_password": True,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/account-recovery/valid-token",
            data={
                "new_password": "new_strong_password",
                "new_password_confirm": "new_strong_password",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 303
        assert "/login?success=password_reset" in response.headers["location"]
        mock_svc.complete_self_service_password_reset.assert_called_once_with(
            TENANT_ID, user_id, "new_strong_password"
        )

    def test_post_password_mismatch(self, mocker):
        _setup(mocker)
        user_id = str(uuid4())
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = {
            "user_id": user_id,
            "is_inactivated": False,
            "has_password": True,
            "role": "member",
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        }

        client = TestClient(app)
        response = client.post(
            "/account-recovery/valid-token",
            data={
                "new_password": "pass_one",
                "new_password_confirm": "pass_two",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 200
        assert "Passwords do not match" in response.text

    def test_post_invalid_token(self, mocker):
        _setup(mocker)
        mock_svc = mocker.patch(f"{AUTH_PW_RESET}.users_service")
        mock_svc.validate_recovery_token.return_value = None

        client = TestClient(app, follow_redirects=False)
        response = client.post(
            "/account-recovery/bad-token",
            data={
                "new_password": "new_password",
                "new_password_confirm": "new_password",
                "csrf_token": "test",
            },
        )

        assert response.status_code == 303
        assert "/forgot-password?error=invalid_or_expired" in response.headers["location"]
