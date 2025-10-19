"""Tests for routers/account.py endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from main import app


def test_account_index_redirects_to_profile(test_user):
    """Test account index redirects to first accessible child."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    client = TestClient(app)
    response = client.get("/account/", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/account/profile"


def test_profile_settings_page(test_user):
    """Test profile settings page renders."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        from fastapi.responses import HTMLResponse

        mock_template.return_value = HTMLResponse(content="<html>Profile</html>")

        client = TestClient(app)
        response = client.get("/account/profile")

        app.dependency_overrides.clear()

        assert response.status_code == 200


def test_update_profile_success(test_user):
    """Test updating user profile."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.users.update_user_profile") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile",
            data={"first_name": "NewFirst", "last_name": "NewLast"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once_with(
            test_user["tenant_id"], test_user["id"], "NewFirst", "NewLast"
        )


def test_update_profile_denied_by_security_setting(test_user):
    """Test profile update denied when security setting disallows it."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.security.can_user_edit_profile") as mock_security:
        with patch("database.users.update_user_profile") as mock_update:
            mock_security.return_value = {"allow_users_edit_profile": False}

            client = TestClient(app)
            response = client.post(
                "/account/profile",
                data={"first_name": "NewFirst", "last_name": "NewLast"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/account/profile"
            mock_update.assert_not_called()


def test_update_timezone_success(test_user):
    """Test updating user timezone."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.users.update_user_timezone") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-timezone",
            data={"timezone": "America/Los_Angeles"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_called_once_with(
            test_user["tenant_id"], test_user["id"], "America/Los_Angeles"
        )


def test_update_timezone_invalid(test_user):
    """Test updating timezone with invalid value."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.users.update_user_timezone") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-timezone",
            data={"timezone": "Invalid/Timezone"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"
        mock_update.assert_not_called()


def test_update_regional_both_valid(test_user):
    """Test updating both timezone and locale."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.users.update_user_timezone_and_locale") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "America/New_York", "locale": "en-US"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        mock_update.assert_called_once_with(
            test_user["tenant_id"], test_user["id"], "America/New_York", "en-US"
        )


def test_update_regional_timezone_only(test_user):
    """Test updating timezone only."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.users.update_user_timezone") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "Europe/London", "locale": ""},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        mock_update.assert_called_once_with(
            test_user["tenant_id"], test_user["id"], "Europe/London"
        )


def test_update_regional_locale_only(test_user):
    """Test updating locale only with invalid timezone."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.users.update_user_locale") as mock_update:
        client = TestClient(app)
        response = client.post(
            "/account/profile/update-regional",
            data={"timezone": "Invalid/Zone", "locale": "fr-FR"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        mock_update.assert_called_once_with(test_user["tenant_id"], test_user["id"], "fr-FR")


def test_email_settings_page(test_user):
    """Test email settings page renders."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.list_user_emails") as mock_list:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from fastapi.responses import HTMLResponse

            mock_list.return_value = []
            mock_template.return_value = HTMLResponse(content="<html>Emails</html>")

            client = TestClient(app)
            response = client.get("/account/emails")

            app.dependency_overrides.clear()

            assert response.status_code == 200
            mock_list.assert_called_once_with(test_user["tenant_id"], test_user["id"])


def test_mfa_settings_page(test_user):
    """Test MFA settings page renders."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.mfa.list_backup_codes") as mock_list:
        with patch("routers.account.templates.TemplateResponse") as mock_template:
            from fastapi.responses import HTMLResponse

            mock_list.return_value = []
            mock_template.return_value = HTMLResponse(content="<html>MFA</html>")

            client = TestClient(app)
            response = client.get("/account/mfa")

            app.dependency_overrides.clear()

            assert response.status_code == 200
            mock_list.assert_called_once_with(test_user["tenant_id"], test_user["id"])


def test_add_email_success(test_user):
    """Test adding a new email address."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.user_emails.add_email") as mock_add:
            with patch("routers.account.send_email_verification") as mock_send:
                mock_exists.return_value = False
                mock_add.return_value = {"id": "email-id", "verify_nonce": 12345}

                client = TestClient(app)
                response = client.post(
                    "/account/emails/add",
                    data={"email": "new@example.com"},
                    follow_redirects=False,
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert response.headers["location"] == "/account/emails"
                mock_add.assert_called_once()
                mock_send.assert_called_once()


def test_add_email_already_exists(test_user):
    """Test adding email that already exists."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.email_exists") as mock_exists:
        with patch("database.user_emails.add_email") as mock_add:
            mock_exists.return_value = True

            client = TestClient(app)
            response = client.post(
                "/account/emails/add",
                data={"email": "existing@example.com"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            mock_add.assert_not_called()


def test_set_primary_email_success(test_user):
    """Test setting an email as primary."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.unset_primary_emails") as mock_unset:
            with patch("database.user_emails.set_primary_email") as mock_set:
                mock_get.return_value = {"id": "email-id", "verified_at": "2024-01-01"}

                client = TestClient(app)
                response = client.post(
                    "/account/emails/set-primary/email-id", follow_redirects=False
                )

                app.dependency_overrides.clear()

                assert response.status_code == 303
                mock_unset.assert_called_once()
                mock_set.assert_called_once_with(test_user["tenant_id"], "email-id")


def test_set_primary_email_unverified(test_user):
    """Test cannot set unverified email as primary."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.set_primary_email") as mock_set:
            mock_get.return_value = {"id": "email-id", "verified_at": None}

            client = TestClient(app)
            response = client.post("/account/emails/set-primary/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            mock_set.assert_not_called()


def test_delete_email_success(test_user):
    """Test deleting a secondary email."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.delete_email") as mock_delete:
            mock_get.return_value = {"id": "email-id", "is_primary": False}

            client = TestClient(app)
            response = client.post("/account/emails/delete/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            mock_delete.assert_called_once_with(test_user["tenant_id"], "email-id")


def test_delete_email_primary_blocked(test_user):
    """Test cannot delete primary email."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.get_email_by_id") as mock_get:
        with patch("database.user_emails.delete_email") as mock_delete:
            mock_get.return_value = {"id": "email-id", "is_primary": True}

            client = TestClient(app)
            response = client.post("/account/emails/delete/email-id", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            mock_delete.assert_not_called()


def test_verify_email_success(test_user):
    """Test email verification with valid nonce."""
    from dependencies import get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.get_email_for_verification") as mock_get:
        with patch("database.user_emails.verify_email") as mock_verify:
            mock_get.return_value = {
                "id": "email-id",
                "verified_at": None,
                "verify_nonce": 12345,
            }

            client = TestClient(app)
            response = client.get("/account/emails/verify/email-id/12345", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/account/emails"
            mock_verify.assert_called_once_with(test_user["tenant_id"], "email-id")


def test_verify_email_invalid_nonce(test_user):
    """Test email verification with invalid nonce."""
    from dependencies import get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.user_emails.get_email_for_verification") as mock_get:
        with patch("database.user_emails.verify_email") as mock_verify:
            mock_get.return_value = {
                "id": "email-id",
                "verified_at": None,
                "verify_nonce": 12345,
            }

            client = TestClient(app)
            response = client.get("/account/emails/verify/email-id/99999", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            mock_verify.assert_not_called()


def test_mfa_setup_totp_get(test_user):
    """Test TOTP setup page GET request."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        with patch("database.user_emails.get_primary_email") as mock_email:
            with patch("database.mfa.create_totp_secret") as mock_create:
                from fastapi.responses import HTMLResponse

                mock_template.return_value = HTMLResponse(content="<html>TOTP Setup</html>")
                mock_email.return_value = {"email": "test@example.com"}

                client = TestClient(app)
                response = client.get("/account/mfa/setup/totp")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_create.assert_called_once()


def test_mfa_setup_totp_already_enabled(test_user):
    """Test TOTP setup redirects when already enabled."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    totp_user = {**test_user, "mfa_method": "totp"}
    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: totp_user
    app.dependency_overrides[require_current_user] = lambda: totp_user

    client = TestClient(app)
    response = client.get("/account/mfa/setup/totp", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/account/mfa"


def test_mfa_setup_email(test_user):
    """Test enabling email MFA."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("database.mfa.enable_mfa") as mock_enable:
        client = TestClient(app)
        response = client.post("/account/mfa/setup/email", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/account/mfa"
        mock_enable.assert_called_once_with(test_user["tenant_id"], test_user["id"], "email")


def test_mfa_regenerate_backup_codes(test_user):
    """Test regenerating backup codes."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    with patch("routers.account.templates.TemplateResponse") as mock_template:
        with patch("database.mfa.delete_backup_codes") as mock_delete:
            with patch("database.mfa.create_backup_code") as mock_create:
                from fastapi.responses import HTMLResponse

                mock_template.return_value = HTMLResponse(content="<html>Backup Codes</html>")

                client = TestClient(app)
                response = client.post("/account/mfa/regenerate-backup-codes")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_delete.assert_called_once()
                # Should create 10 backup codes
                assert mock_create.call_count == 10


def test_mfa_downgrade_verify_page_no_pending(test_user):
    """Test downgrade verify page redirects without pending session."""
    from dependencies import get_current_user, get_tenant_id_from_request, require_current_user

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
    app.dependency_overrides[get_current_user] = lambda: test_user
    app.dependency_overrides[require_current_user] = lambda: test_user

    client = TestClient(app)
    response = client.get("/account/mfa/downgrade-verify", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/account/mfa"
