"""Tests for the tenant provisioning CLI."""

import argparse
from unittest.mock import patch

import pytest


def _make_args(**overrides):
    """Build a Namespace with valid defaults, applying overrides."""
    defaults = {
        "subdomain": "acme",
        "tenant_name": "Acme Corp",
        "email": "admin@acme.com",
        "first_name": "Jane",
        "last_name": "Smith",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ============================================================================
# Validation tests
# ============================================================================


class TestValidation:
    """Input validation runs before any DB writes."""

    def test_valid_args_pass(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args())
        assert errors == []

    def test_invalid_subdomain_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(subdomain="INVALID"))
        assert any("subdomain" in e.lower() for e in errors)

    def test_empty_email_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(email=""))
        assert any("email" in e.lower() for e in errors)

    def test_email_without_at_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(email="not-an-email"))
        assert any("email" in e.lower() for e in errors)

    def test_empty_first_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(first_name=""))
        assert any("first name" in e.lower() for e in errors)

    def test_long_first_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(first_name="A" * 256))
        assert any("first name" in e.lower() for e in errors)

    def test_empty_last_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(last_name=""))
        assert any("last name" in e.lower() for e in errors)

    def test_long_last_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(last_name="B" * 256))
        assert any("last name" in e.lower() for e in errors)

    def test_empty_tenant_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(tenant_name=""))
        assert any("tenant name" in e.lower() for e in errors)

    def test_long_tenant_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(tenant_name="X" * 81))
        assert any("tenant name" in e.lower() for e in errors)

    def test_whitespace_only_first_name_rejected(self):
        from cli.provision_tenant import _validate_args

        errors = _validate_args(_make_args(first_name="   "))
        assert any("first name" in e.lower() for e in errors)

    def test_validation_errors_prevent_db_writes(self):
        from cli.provision_tenant import main

        args = _make_args(subdomain="INVALID", email="bad")
        with patch("cli.provision_tenant.provision_tenant") as mock_provision:
            exit_code = main(args)
            assert exit_code == 1
            mock_provision.assert_not_called()


# ============================================================================
# Happy path
# ============================================================================


class TestHappyPath:
    """Full provisioning flow with all mocks."""

    @pytest.fixture(autouse=True)
    def _setup_mocks(self):
        """Set up all mocks for the happy path."""
        self.patches = {
            "provision_tenant": patch("cli.provision_tenant.provision_tenant"),
            "get_tenant": patch("cli.provision_tenant.database.tenants.get_tenant_by_subdomain"),
            "email_exists": patch("cli.provision_tenant.email_exists"),
            "create_user": patch("cli.provision_tenant.create_user_raw"),
            "add_email": patch("cli.provision_tenant.add_unverified_email_with_nonce"),
            "log_event": patch("cli.provision_tenant.log_event"),
            "send_email": patch("cli.provision_tenant.send_provisioning_invitation"),
            "settings": patch("cli.provision_tenant.settings"),
        }

        self.mocks = {}
        for name, p in self.patches.items():
            self.mocks[name] = p.start()

        # Configure default return values
        self.mocks["get_tenant"].return_value = {"id": "tenant-uuid-123"}
        self.mocks["email_exists"].return_value = False
        self.mocks["create_user"].return_value = {"user_id": "user-uuid-456"}
        self.mocks["add_email"].return_value = {
            "id": "email-uuid-789",
            "verify_nonce": "nonce-abc",
        }
        self.mocks["send_email"].return_value = True
        self.mocks["settings"].BASE_DOMAIN = "example.com"

        yield

        for p in self.patches.values():
            p.stop()

    def test_successful_provisioning(self):
        from cli.provision_tenant import main

        exit_code = main(_make_args())
        assert exit_code == 0

    def test_provisions_tenant(self):
        from cli.provision_tenant import main

        main(_make_args())
        self.mocks["provision_tenant"].assert_called_once_with("acme", "Acme Corp")

    def test_creates_super_admin(self):
        from cli.provision_tenant import main

        main(_make_args())
        self.mocks["create_user"].assert_called_once_with(
            "tenant-uuid-123", "Jane", "Smith", "admin@acme.com", "super_admin"
        )

    def test_adds_unverified_email(self):
        from cli.provision_tenant import main

        main(_make_args())
        self.mocks["add_email"].assert_called_once_with(
            "tenant-uuid-123", "user-uuid-456", "admin@acme.com"
        )

    def test_logs_event_with_cli_source(self):
        from cli.provision_tenant import main

        main(_make_args())
        self.mocks["log_event"].assert_called_once()
        call_kwargs = self.mocks["log_event"].call_args[1]
        assert call_kwargs["tenant_id"] == "tenant-uuid-123"
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["artifact_id"] == "user-uuid-456"
        assert call_kwargs["event_type"] == "user_created"
        assert call_kwargs["metadata"]["source"] == "cli"
        assert call_kwargs["metadata"]["role"] == "super_admin"

    def test_sends_invitation_email(self):
        from cli.provision_tenant import main

        main(_make_args())
        self.mocks["send_email"].assert_called_once()
        call_args = self.mocks["send_email"].call_args[0]
        assert call_args[0] == "admin@acme.com"
        assert call_args[1] == "Acme Corp"
        assert "acme.example.com" in call_args[2]
        assert "email-uuid-789" in call_args[2]
        assert "nonce-abc" in call_args[2]

    def test_verification_url_format(self):
        from cli.provision_tenant import main

        main(_make_args())
        call_args = self.mocks["send_email"].call_args[0]
        expected = "https://acme.example.com/verify-email/email-uuid-789/nonce-abc"
        assert call_args[2] == expected


# ============================================================================
# Idempotent tenant creation
# ============================================================================


class TestIdempotentTenant:
    """Existing tenant is reused without error."""

    def test_existing_tenant_reused(self):
        from cli.provision_tenant import main

        with (
            patch("cli.provision_tenant.provision_tenant") as mock_provision,
            patch(
                "cli.provision_tenant.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "existing-tenant-id"},
            ),
            patch("cli.provision_tenant.email_exists", return_value=False),
            patch(
                "cli.provision_tenant.create_user_raw",
                return_value={"user_id": "new-user-id"},
            ),
            patch(
                "cli.provision_tenant.add_unverified_email_with_nonce",
                return_value={"id": "eid", "verify_nonce": "nonce"},
            ),
            patch("cli.provision_tenant.log_event"),
            patch("cli.provision_tenant.send_provisioning_invitation", return_value=True),
            patch("cli.provision_tenant.settings") as mock_settings,
        ):
            mock_settings.BASE_DOMAIN = "example.com"
            exit_code = main(_make_args())

            assert exit_code == 0
            mock_provision.assert_called_once()


# ============================================================================
# Error cases
# ============================================================================


class TestErrorCases:
    """Error handling for various failure modes."""

    def test_duplicate_email_aborts(self, capsys):
        from cli.provision_tenant import main

        with (
            patch("cli.provision_tenant.provision_tenant"),
            patch(
                "cli.provision_tenant.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "tid"},
            ),
            patch("cli.provision_tenant.email_exists", return_value=True),
            patch("cli.provision_tenant.create_user_raw") as mock_create,
        ):
            exit_code = main(_make_args())

            assert exit_code == 1
            mock_create.assert_not_called()
            captured = capsys.readouterr()
            assert "already exists" in captured.err

    def test_tenant_lookup_failure_aborts(self, capsys):
        from cli.provision_tenant import main

        with (
            patch("cli.provision_tenant.provision_tenant"),
            patch(
                "cli.provision_tenant.database.tenants.get_tenant_by_subdomain",
                return_value=None,
            ),
        ):
            exit_code = main(_make_args())
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "Failed to create or find tenant" in captured.err

    def test_user_creation_failure_aborts(self, capsys):
        from cli.provision_tenant import main

        with (
            patch("cli.provision_tenant.provision_tenant"),
            patch(
                "cli.provision_tenant.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "tid"},
            ),
            patch("cli.provision_tenant.email_exists", return_value=False),
            patch("cli.provision_tenant.create_user_raw", return_value=None),
        ):
            exit_code = main(_make_args())
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "Failed to create user" in captured.err

    def test_email_add_failure_aborts(self, capsys):
        from cli.provision_tenant import main

        with (
            patch("cli.provision_tenant.provision_tenant"),
            patch(
                "cli.provision_tenant.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "tid"},
            ),
            patch("cli.provision_tenant.email_exists", return_value=False),
            patch(
                "cli.provision_tenant.create_user_raw",
                return_value={"user_id": "uid"},
            ),
            patch(
                "cli.provision_tenant.add_unverified_email_with_nonce",
                return_value=None,
            ),
        ):
            exit_code = main(_make_args())
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "Failed to add email" in captured.err

    def test_email_delivery_failure_warns_but_succeeds(self, capsys):
        from cli.provision_tenant import main

        with (
            patch("cli.provision_tenant.provision_tenant"),
            patch(
                "cli.provision_tenant.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "tid"},
            ),
            patch("cli.provision_tenant.email_exists", return_value=False),
            patch(
                "cli.provision_tenant.create_user_raw",
                return_value={"user_id": "uid"},
            ),
            patch(
                "cli.provision_tenant.add_unverified_email_with_nonce",
                return_value={"id": "eid", "verify_nonce": "nonce"},
            ),
            patch("cli.provision_tenant.log_event"),
            patch("cli.provision_tenant.send_provisioning_invitation", return_value=False),
            patch("cli.provision_tenant.settings") as mock_settings,
        ):
            mock_settings.BASE_DOMAIN = "example.com"
            exit_code = main(_make_args())

            assert exit_code == 0
            captured = capsys.readouterr()
            assert "Warning" in captured.err or "Failed to send" in captured.err
            # Verification URL printed as fallback
            assert "verify-email" in captured.out


# ============================================================================
# CLI argument parsing
# ============================================================================


class TestCliParsing:
    """Argument parsing works correctly."""

    def test_cli_calls_main(self):
        from cli.provision_tenant import cli

        with (
            patch("cli.provision_tenant.main", return_value=0) as mock_main,
            patch(
                "sys.argv",
                [
                    "provision_tenant",
                    "--subdomain",
                    "test",
                    "--tenant-name",
                    "Test Co",
                    "--email",
                    "a@b.com",
                    "--first-name",
                    "A",
                    "--last-name",
                    "B",
                ],
            ),
        ):
            exit_code = cli()
            assert exit_code == 0
            mock_main.assert_called_once()
            args = mock_main.call_args[0][0]
            assert args.subdomain == "test"
            assert args.tenant_name == "Test Co"
            assert args.email == "a@b.com"
            assert args.first_name == "A"
            assert args.last_name == "B"

    def test_missing_required_args_exits(self):
        from cli.provision_tenant import cli

        with patch("sys.argv", ["provision_tenant"]), pytest.raises(SystemExit) as exc:
            cli()
        assert exc.value.code == 2
