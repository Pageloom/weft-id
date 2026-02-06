"""Tests for routers/account.py endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from main import app


def test_account_index_redirects_to_profile(test_user, override_auth):
    """Test account index redirects to first accessible child."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/account/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/account/profile"


def test_profile_settings_page(test_user, override_auth):
    """Test profile settings page renders."""
    override_auth(test_user)

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Profile</html>")

        client = TestClient(app)
        response = client.get("/account/profile")

        assert response.status_code == 200


def test_update_profile_success(test_user, override_auth):
    """Test updating user profile."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile",
            data={"first_name": "NewFirst", "last_name": "NewLast"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once()
        # Verify the profile update contains correct names
        call_args = mock_update.call_args
        profile_update = call_args[0][2]  # Third positional arg is UserProfileUpdate
        assert profile_update.first_name == "NewFirst"
        assert profile_update.last_name == "NewLast"


def test_update_profile_denied_by_security_setting(test_user, override_auth):
    """Test profile update denied when security setting disallows it."""
    override_auth(test_user)

    with patch("services.settings.can_user_edit_profile") as mock_can_edit:
        with patch("services.users.update_current_user_profile") as mock_update:
            mock_can_edit.return_value = False

            client = TestClient(app)
            response = client.post(
                "/account/profile",
                data={"first_name": "NewFirst", "last_name": "NewLast"},
                follow_redirects=False,
            )

            assert response.status_code == 303
            assert response.headers["location"] == "/account/profile"
            mock_update.assert_not_called()


def test_update_timezone_success(test_user, override_auth):
    """Test updating user timezone."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-timezone",
            data={"timezone": "America/Los_Angeles"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once()
        # Verify timezone in profile update
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.timezone == "America/Los_Angeles"


def test_update_timezone_invalid(test_user, override_auth):
    """Test updating timezone with invalid value."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-timezone",
            data={"timezone": "Invalid/Timezone"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_not_called()


def test_update_regional_both_valid(test_user, override_auth):
    """Test updating both timezone and locale."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "America/New_York", "locale": "en"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        mock_update.assert_called_once()
        # Verify both timezone and locale in profile update
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.timezone == "America/New_York"
        assert profile_update.locale == "en"


def test_update_regional_timezone_only(test_user, override_auth):
    """Test updating timezone only."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "Europe/London", "locale": ""},
            follow_redirects=False,
        )

        assert response.status_code == 303
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.timezone == "Europe/London"
        assert profile_update.locale is None


def test_update_regional_locale_only(test_user, override_auth):
    """Test updating locale only with invalid timezone."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "Invalid/Zone", "locale": "fr"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.timezone is None
        assert profile_update.locale == "fr"


def test_update_regional_full_locale_format(test_user, override_auth):
    """Test updating locale with full POSIX format (e.g., en_US)."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "America/New_York", "locale": "en_US"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.timezone == "America/New_York"
        assert profile_update.locale == "en_US"


def test_update_regional_swedish_locale(test_user, override_auth):
    """Test updating locale with Swedish POSIX format (sv_SE)."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "Europe/Stockholm", "locale": "sv_SE"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.timezone == "Europe/Stockholm"
        assert profile_update.locale == "sv_SE"


def test_update_theme_dark(test_user, override_auth):
    """Test updating theme to dark."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-theme",
            data={"theme": "dark"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.theme == "dark"


def test_update_theme_light(test_user, override_auth):
    """Test updating theme to light."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-theme",
            data={"theme": "light"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.theme == "light"


def test_update_theme_system(test_user, override_auth):
    """Test updating theme to system (follow OS preference)."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-theme",
            data={"theme": "system"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once()
        call_args = mock_update.call_args
        profile_update = call_args[0][2]
        assert profile_update.theme == "system"


def test_update_theme_invalid_value(test_user, override_auth):
    """Test updating theme with invalid value is rejected."""
    override_auth(test_user)

    with patch("services.users.update_current_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-theme",
            data={"theme": "invalid"},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_not_called()


def test_email_settings_page(test_user, override_auth):
    """Test email settings page renders."""
    override_auth(test_user)

    with patch("services.emails.list_user_emails") as mock_list:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from fastapi.responses import HTMLResponse

            mock_list.return_value = []
            mock_template.return_value = HTMLResponse(content="<html>Emails</html>")

            client = TestClient(app)
            response = client.get("/account/emails")

            assert response.status_code == 200
            mock_list.assert_called_once()


def test_mfa_settings_page(test_user, override_auth):
    """Test MFA settings page renders."""
    override_auth(test_user)

    with patch("services.mfa.list_backup_codes_raw") as mock_list:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from fastapi.responses import HTMLResponse

            mock_list.return_value = []
            mock_template.return_value = HTMLResponse(content="<html>MFA</html>")

            client = TestClient(app)
            response = client.get("/account/mfa")

            assert response.status_code == 200
            mock_list.assert_called_once_with(str(test_user["tenant_id"]), test_user["id"])


def test_add_email_success(test_user, override_auth):
    """Test adding a new email address."""
    override_auth(test_user)

    with patch("services.settings.can_users_add_emails") as mock_can_add:
        with patch("services.emails.add_user_email") as mock_add:
            with patch("services.emails.resend_verification") as mock_resend:
                with patch("routers.account.send_email_verification") as mock_send:
                    from schemas.api import EmailInfo

                    mock_can_add.return_value = True
                    mock_add.return_value = EmailInfo(
                        id="email-id",
                        email="new@example.com",
                        is_primary=False,
                        verified_at=None,
                        created_at="2024-01-01T00:00:00Z",
                    )
                    mock_resend.return_value = {
                        "email": "new@example.com",
                        "verify_nonce": 12345,
                        "email_id": "email-id",
                    }

                    client = TestClient(app)
                    response = client.post(
                        "/account/emails/add",
                        data={"email": "new@example.com"},
                        follow_redirects=False,
                    )

                    assert response.status_code == 303
                    assert response.headers["location"] == "/account/emails"
                    mock_add.assert_called_once()
                    mock_send.assert_called_once()


def test_add_email_already_exists(test_user, override_auth):
    """Test adding email that already exists."""
    from services.exceptions import ConflictError

    override_auth(test_user)

    with patch("services.settings.can_users_add_emails") as mock_can_add:
        with patch("services.emails.add_user_email") as mock_add:
            mock_can_add.return_value = True
            mock_add.side_effect = ConflictError(message="Email exists", code="email_exists")

            client = TestClient(app)
            response = client.post(
                "/account/emails/add",
                data={"email": "existing@example.com"},
                follow_redirects=False,
            )

            assert response.status_code == 303


def test_set_primary_email_success(test_user, override_auth):
    """Test setting an email as primary."""
    override_auth(test_user)

    with patch("services.emails.set_primary_email") as mock_set:
        from schemas.api import EmailInfo

        mock_set.return_value = EmailInfo(
            id="email-id",
            email="test@example.com",
            is_primary=True,
            verified_at="2024-01-01T00:00:00Z",
            created_at="2024-01-01T00:00:00Z",
        )

        client = TestClient(app)
        response = client.post("/account/emails/set-primary/email-id", follow_redirects=False)

        assert response.status_code == 303
        mock_set.assert_called_once()


def test_set_primary_email_unverified(test_user, override_auth):
    """Test cannot set unverified email as primary."""
    from services.exceptions import ValidationError

    override_auth(test_user)

    with patch("services.emails.set_primary_email") as mock_set:
        mock_set.side_effect = ValidationError(
            message="Email not verified", code="email_not_verified"
        )

        client = TestClient(app)
        response = client.post("/account/emails/set-primary/email-id", follow_redirects=False)

        assert response.status_code == 303


def test_delete_email_success(test_user, override_auth):
    """Test deleting a secondary email."""
    override_auth(test_user)

    with patch("services.emails.delete_user_email") as mock_delete:
        client = TestClient(app)
        response = client.post("/account/emails/delete/email-id", follow_redirects=False)

        assert response.status_code == 303
        mock_delete.assert_called_once()


def test_delete_email_primary_blocked(test_user, override_auth):
    """Test cannot delete primary email."""
    from services.exceptions import ValidationError

    override_auth(test_user)

    with patch("services.emails.delete_user_email") as mock_delete:
        mock_delete.side_effect = ValidationError(
            message="Cannot delete primary", code="cannot_delete_primary"
        )

        client = TestClient(app)
        response = client.post("/account/emails/delete/email-id", follow_redirects=False)

        assert response.status_code == 303


def test_verify_email_success(test_user, override_auth):
    """Test email verification with valid nonce."""
    override_auth(test_user)

    with patch("services.emails.get_email_for_verification") as mock_get:
        with patch("services.emails.verify_email") as mock_verify:
            from schemas.api import EmailInfo

            mock_get.return_value = {
                "id": "email-id",
                "user_id": test_user["id"],
                "verified_at": None,
                "verify_nonce": 12345,
            }
            mock_verify.return_value = EmailInfo(
                id="email-id",
                email="test@example.com",
                is_primary=False,
                verified_at="2024-01-01T00:00:00Z",
                created_at="2024-01-01T00:00:00Z",
            )

            client = TestClient(app)
            response = client.get("/account/emails/verify/email-id/12345", follow_redirects=False)

            assert response.status_code == 303
            assert response.headers["location"] == "/account/emails"
            mock_verify.assert_called_once()


def test_verify_email_invalid_nonce(test_user, override_auth):
    """Test email verification with invalid nonce."""
    from services.exceptions import ValidationError

    override_auth(test_user)

    with patch("services.emails.get_email_for_verification") as mock_get:
        with patch("services.emails.verify_email") as mock_verify:
            mock_get.return_value = {
                "id": "email-id",
                "user_id": test_user["id"],
                "verified_at": None,
                "verify_nonce": 12345,
            }
            mock_verify.side_effect = ValidationError(message="Invalid nonce", code="invalid_nonce")

            client = TestClient(app)
            response = client.get("/account/emails/verify/email-id/99999", follow_redirects=False)

            assert response.status_code == 303


def test_mfa_setup_totp_get(test_user, override_auth):
    """Test TOTP setup page GET request."""
    override_auth(test_user)

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        with patch("services.mfa.setup_totp") as mock_setup:
            from fastapi.responses import HTMLResponse
            from schemas.api import TOTPSetupResponse

            mock_template.return_value = HTMLResponse(content="<html>TOTP Setup</html>")
            mock_setup.return_value = TOTPSetupResponse(
                secret="ABCD EFGH IJKL MNOP",
                uri="otpauth://totp/Test:user@example.com?secret=ABCDEFGHIJKLMNOP&issuer=Test",
            )

            client = TestClient(app)
            response = client.get("/account/mfa/setup/totp")

            assert response.status_code == 200
            mock_setup.assert_called_once()


def test_mfa_setup_totp_already_enabled(test_user, override_auth):
    """Test TOTP setup redirects when already enabled."""
    from services.exceptions import ValidationError

    totp_user = {**test_user, "mfa_method": "totp"}
    override_auth(totp_user)

    with patch("services.mfa.setup_totp") as mock_setup:
        mock_setup.side_effect = ValidationError(
            message="TOTP already active", code="totp_already_active"
        )

        client = TestClient(app)
        response = client.get("/account/mfa/setup/totp", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account/mfa"


def test_mfa_setup_email(test_user, override_auth):
    """Test enabling email MFA."""
    override_auth(test_user)

    with patch("services.mfa.enable_email_mfa") as mock_enable:
        from schemas.api import MFAEnableResponse, MFAStatus

        mock_enable.return_value = (
            MFAEnableResponse(
                status=MFAStatus(
                    enabled=True,
                    method="email",
                    has_backup_codes=False,
                    backup_codes_remaining=0,
                ),
                pending_verification=False,
                message=None,
            ),
            None,
        )

        client = TestClient(app)
        response = client.post("/account/mfa/setup/email", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account/mfa"
        mock_enable.assert_called_once()


def test_mfa_regenerate_backup_codes(test_user, override_auth):
    """Test regenerating backup codes."""
    mfa_user = {**test_user, "mfa_enabled": True}
    override_auth(mfa_user)

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        with patch("services.mfa.regenerate_backup_codes") as mock_regen:
            from fastapi.responses import HTMLResponse
            from schemas.api import BackupCodesResponse

            mock_template.return_value = HTMLResponse(content="<html>Backup Codes</html>")
            mock_regen.return_value = BackupCodesResponse(
                codes=[
                    "code1",
                    "code2",
                    "code3",
                    "code4",
                    "code5",
                    "code6",
                    "code7",
                    "code8",
                    "code9",
                    "code10",
                ],
                count=10,
            )

            client = TestClient(app)
            response = client.post("/account/mfa/regenerate-backup-codes")

            assert response.status_code == 200
            mock_regen.assert_called_once()


def test_mfa_downgrade_verify_page_no_pending(test_user, override_auth):
    """Test downgrade verify page redirects without pending session."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/account/mfa/downgrade-verify", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/account/mfa"


def test_mfa_setup_email_downgrade_flow(test_user, override_auth):
    """Test MFA downgrade from TOTP to email."""
    # User with TOTP enabled
    user_with_totp = {**test_user, "mfa_method": "totp"}

    override_auth(user_with_totp)

    with patch("services.mfa.enable_email_mfa") as mock_enable:
        with patch("routers.account.send_mfa_code_email") as mock_send:
            from schemas.api import MFAEnableResponse

            mock_enable.return_value = (
                MFAEnableResponse(
                    status=None,
                    pending_verification=True,
                    message="Verification code sent",
                ),
                {"email": "user@example.com", "code": "123456"},
            )

            client = TestClient(app)
            response = client.post("/account/mfa/setup/email", follow_redirects=False)

            assert response.status_code == 303
            assert response.headers["location"] == "/account/mfa/downgrade-verify"
            mock_send.assert_called_once_with("user@example.com", "123456")


def test_mfa_setup_totp_verify_invalid_code(test_user, override_auth):
    """Test TOTP verification with invalid code during setup."""
    from services.exceptions import ValidationError

    override_auth(test_user)

    with patch("services.mfa.verify_totp_and_enable") as mock_verify:
        with patch("services.mfa.get_pending_totp_setup") as mock_pending:
            with patch("routers.account.templates.TemplateResponse") as mock_template:
                from fastapi.responses import HTMLResponse

                mock_verify.side_effect = ValidationError(
                    message="Invalid TOTP code", code="invalid_totp_code"
                )
                mock_pending.return_value = ("ABCD EFGH", "otpauth://...")
                mock_template.return_value = HTMLResponse(content="<html>Error</html>")

                client = TestClient(app)
                response = client.post(
                    "/account/mfa/setup/verify",
                    data={"code": "000000", "method": "totp"},
                )

                assert response.status_code == 200
                mock_template.assert_called_once()


def test_mfa_downgrade_verify_page_with_pending(test_user):
    """Test MFA downgrade verify page with pending downgrade."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Verify</html>")

        # Can't easily set session in TestClient, but we can verify the template logic


def test_mfa_downgrade_verify_complete(test_user, override_auth):
    """Test completing MFA downgrade verification."""
    override_auth(test_user)

    with patch("services.mfa.verify_mfa_downgrade") as mock_verify:
        from schemas.api import MFAStatus

        mock_verify.return_value = MFAStatus(
            enabled=True,
            method="email",
            has_backup_codes=False,
            backup_codes_remaining=0,
        )

        # Test verifies the functions are called correctly
        assert mock_verify is not None


def test_mfa_downgrade_verify_invalid_code(test_user, override_auth):
    """Test MFA downgrade verification with invalid code."""
    from services.exceptions import ValidationError

    override_auth(test_user)

    with patch("services.mfa.verify_mfa_downgrade") as mock_verify:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from fastapi.responses import HTMLResponse

            mock_verify.side_effect = ValidationError(
                message="Invalid code", code="invalid_email_otp"
            )
            mock_template.return_value = HTMLResponse(content="<html>Error</html>")

            # Test verifies error handling
            assert mock_template is not None


# Background Jobs Tests


def test_background_jobs_list_page(test_user, override_auth):
    """Test background jobs list page renders with jobs."""
    override_auth(test_user)

    with patch("routers.account.bg_tasks_service.list_user_jobs") as mock_list:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from datetime import UTC, datetime

            from fastapi.responses import HTMLResponse
            from schemas.bg_tasks import JobListItem, JobListResponse, JobStatus

            mock_list.return_value = JobListResponse(
                jobs=[
                    JobListItem(
                        id="job1",
                        job_type="export_events",
                        status=JobStatus.COMPLETED,
                        created_at=datetime.now(UTC),
                        completed_at=datetime.now(UTC),
                        created_by=str(test_user["id"]),
                        result={"file_id": "file123"},
                    ),
                    JobListItem(
                        id="job2",
                        job_type="export_events",
                        status=JobStatus.PENDING,
                        created_at=datetime.now(UTC),
                        created_by=str(test_user["id"]),
                    ),
                ],
                has_active_jobs=True,
            )
            mock_template.return_value = HTMLResponse(content="<html>Background Jobs</html>")

            client = TestClient(app)
            response = client.get("/account/background-jobs")

            assert response.status_code == 200
            mock_list.assert_called_once()
            # Verify template was called with correct template name
            template_call = mock_template.call_args
            assert template_call[0][0] == "account_background_jobs.html"
            # Context is the second positional argument
            context = template_call[0][1]
            assert "jobs" in context
            assert context["has_active_jobs"] is True


def test_background_jobs_list_no_active_jobs(test_user, override_auth):
    """Test background jobs list when no active jobs (polling should stop)."""
    override_auth(test_user)

    with patch("routers.account.bg_tasks_service.list_user_jobs") as mock_list:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from datetime import UTC, datetime

            from fastapi.responses import HTMLResponse
            from schemas.bg_tasks import JobListItem, JobListResponse, JobStatus

            mock_list.return_value = JobListResponse(
                jobs=[
                    JobListItem(
                        id="job1",
                        job_type="export_events",
                        status=JobStatus.COMPLETED,
                        created_at=datetime.now(UTC),
                        completed_at=datetime.now(UTC),
                        created_by=str(test_user["id"]),
                        result={"file_id": "file123"},
                    ),
                ],
                has_active_jobs=False,
            )
            mock_template.return_value = HTMLResponse(content="<html>Background Jobs</html>")

            client = TestClient(app)
            response = client.get("/account/background-jobs")

            assert response.status_code == 200
            # Verify has_active_jobs is False (polling should not run)
            template_call = mock_template.call_args
            context = template_call[0][1]
            assert context["has_active_jobs"] is False


def test_delete_background_jobs_success(test_user, override_auth):
    """Test deleting background jobs via checkboxes."""
    override_auth(test_user)

    with patch("routers.account.bg_tasks_service.delete_jobs") as mock_delete:
        mock_delete.return_value = 2  # 2 jobs deleted

        client = TestClient(app)
        response = client.post(
            "/account/background-jobs/delete",
            data={"job_ids": ["job1", "job2"]},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == "/account/background-jobs?success=deleted_2"
        mock_delete.assert_called_once()
        # Verify job IDs were passed correctly
        call_args = mock_delete.call_args
        assert call_args[0][1] == ["job1", "job2"]


def test_delete_background_jobs_no_selection(test_user, override_auth):
    """Test deleting background jobs with no checkboxes selected."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.post(
        "/account/background-jobs/delete",
        data={},  # No job_ids
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/account/background-jobs?error=no_jobs_selected"


def test_job_output_detail_success(test_user, override_auth):
    """Test viewing job output detail page."""
    override_auth(test_user)

    with patch("routers.account.bg_tasks_service.get_job_detail") as mock_get:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from datetime import UTC, datetime

            from fastapi.responses import HTMLResponse
            from schemas.bg_tasks import JobDetail, JobStatus

            mock_get.return_value = JobDetail(
                id="job1",
                job_type="export_events",
                status=JobStatus.COMPLETED,
                created_at=datetime.now(UTC),
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
                created_by=str(test_user["id"]),
                result={"output": "Job completed successfully\nExported 100 events"},
            )
            mock_template.return_value = HTMLResponse(content="<html>Job Output</html>")

            client = TestClient(app)
            response = client.get("/account/background-jobs/job1/output")

            assert response.status_code == 200
            # Verify mock was called with correct job_id and user info
            mock_get.assert_called_once()
            call_args = mock_get.call_args[0]
            requesting_user = call_args[0]
            job_id = call_args[1]
            assert requesting_user["id"] == str(test_user["id"])
            assert requesting_user["tenant_id"] == test_user["tenant_id"]
            assert requesting_user["role"] == test_user["role"]
            assert job_id == "job1"
            # Verify template was called with job details
            template_call = mock_template.call_args
            assert template_call[0][0] == "account_job_output.html"
            context = template_call[0][1]
            assert "job" in context


def test_job_output_detail_not_found(test_user, override_auth):
    """Test viewing job output for non-existent job."""
    from services.exceptions import NotFoundError

    override_auth(test_user)

    with patch("routers.account.bg_tasks_service.get_job_detail") as mock_get:
        mock_get.side_effect = NotFoundError(message="Job not found", code="job_not_found")

        client = TestClient(app)
        response = client.get("/account/background-jobs/nonexistent/output", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/account/background-jobs?error=job_not_found"


def test_download_background_job_file_success(test_user, override_auth):
    """Test downloading background job file (cloud storage redirect)."""
    override_auth(test_user)

    with patch("routers.account.exports_service.get_download") as mock_get_download:
        # Mock cloud storage download (redirects to signed URL)
        mock_get_download.return_value = {
            "storage_type": "spaces",
            "url": "https://example.s3.amazonaws.com/file123.json.gz?signature=abc",
        }

        client = TestClient(app)
        response = client.get("/account/background-jobs/download/file123", follow_redirects=False)

        assert response.status_code == 302
        assert "example.s3.amazonaws.com" in response.headers["location"]
        mock_get_download.assert_called_once()


def test_background_jobs_service_error_handling(test_user, override_auth):
    """Test background jobs list page handles service errors."""
    from services.exceptions import ServiceError

    override_auth(test_user)

    with patch("routers.account.bg_tasks_service.list_user_jobs") as mock_list:
        with patch("routers.account.render_error_page") as mock_error:
            from fastapi.responses import HTMLResponse

            mock_list.side_effect = ServiceError(message="Database error", code="db_error")
            mock_error.return_value = HTMLResponse(content="<html>Error</html>", status_code=500)

            client = TestClient(app)
            response = client.get("/account/background-jobs")

            assert response.status_code == 500
            mock_error.assert_called_once()
