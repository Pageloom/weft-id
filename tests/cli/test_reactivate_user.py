"""Tests for the user reactivation CLI."""

import argparse
from unittest.mock import patch
from uuid import uuid4

import pytest


def _make_args(**overrides):
    """Build a Namespace with valid defaults, applying overrides."""
    defaults = {
        "subdomain": "acme",
        "email": "admin@acme.com",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ============================================================================
# Happy path
# ============================================================================


class TestHappyPath:
    """Full reactivation flow with all mocks."""

    @pytest.fixture(autouse=True)
    def _setup_mocks(self):
        """Set up all mocks for the happy path."""
        self.user_id = str(uuid4())
        self.tenant_id = str(uuid4())

        self.patches = {
            "get_tenant": patch("cli.reactivate_user.database.tenants.get_tenant_by_subdomain"),
            "get_user": patch("cli.reactivate_user.database.users.get_user_by_email_with_status"),
            "reactivate": patch("cli.reactivate_user.database.users.reactivate_user"),
            "clear_denied": patch("cli.reactivate_user.database.users.clear_reactivation_denied"),
            "log_event": patch("cli.reactivate_user.log_event"),
        }

        self.mocks = {}
        for name, p in self.patches.items():
            self.mocks[name] = p.start()

        # Configure default return values
        self.mocks["get_tenant"].return_value = {"id": self.tenant_id}
        self.mocks["get_user"].return_value = {
            "id": self.user_id,
            "first_name": "Jane",
            "last_name": "Smith",
            "role": "super_admin",
            "inactivated_at": "2026-01-01T00:00:00",
        }

        yield

        for p in self.patches.values():
            p.stop()

    def test_successful_reactivation(self):
        from cli.reactivate_user import main

        exit_code = main(_make_args())
        assert exit_code == 0

    def test_calls_reactivate(self):
        from cli.reactivate_user import main

        main(_make_args())
        self.mocks["reactivate"].assert_called_once_with(self.tenant_id, self.user_id)

    def test_clears_reactivation_denied(self):
        from cli.reactivate_user import main

        main(_make_args())
        self.mocks["clear_denied"].assert_called_once_with(self.tenant_id, self.user_id)

    def test_logs_event_with_cli_source(self):
        from cli.reactivate_user import main

        main(_make_args())
        self.mocks["log_event"].assert_called_once()
        call_kwargs = self.mocks["log_event"].call_args[1]
        assert call_kwargs["tenant_id"] == self.tenant_id
        assert call_kwargs["artifact_type"] == "user"
        assert call_kwargs["artifact_id"] == self.user_id
        assert call_kwargs["event_type"] == "user_reactivated_cli"
        assert call_kwargs["metadata"]["source"] == "cli"
        assert call_kwargs["metadata"]["role"] == "super_admin"

    def test_normalizes_email(self):
        from cli.reactivate_user import main

        main(_make_args(email="  Admin@Acme.COM  "))
        call_args = self.mocks["get_user"].call_args[0]
        assert call_args[1] == "admin@acme.com"

    def test_output_shows_user_info(self, capsys):
        from cli.reactivate_user import main

        main(_make_args())
        captured = capsys.readouterr()
        assert "Jane Smith" in captured.out
        assert "super_admin" in captured.out


# ============================================================================
# Error cases
# ============================================================================


class TestErrorCases:
    """Error handling for various failure modes."""

    def test_invalid_email_aborts(self, capsys):
        from cli.reactivate_user import main

        exit_code = main(_make_args(email="not-an-email"))
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid email" in captured.err

    def test_empty_email_aborts(self, capsys):
        from cli.reactivate_user import main

        exit_code = main(_make_args(email=""))
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid email" in captured.err

    def test_tenant_not_found_aborts(self, capsys):
        from cli.reactivate_user import main

        with patch(
            "cli.reactivate_user.database.tenants.get_tenant_by_subdomain",
            return_value=None,
        ):
            exit_code = main(_make_args())
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "not found" in captured.err

    def test_user_not_found_aborts(self, capsys):
        from cli.reactivate_user import main

        with (
            patch(
                "cli.reactivate_user.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "tid"},
            ),
            patch(
                "cli.reactivate_user.database.users.get_user_by_email_with_status",
                return_value=None,
            ),
        ):
            exit_code = main(_make_args())
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "No user found" in captured.err

    def test_already_active_user_aborts(self, capsys):
        from cli.reactivate_user import main

        with (
            patch(
                "cli.reactivate_user.database.tenants.get_tenant_by_subdomain",
                return_value={"id": "tid"},
            ),
            patch(
                "cli.reactivate_user.database.users.get_user_by_email_with_status",
                return_value={
                    "id": str(uuid4()),
                    "first_name": "Active",
                    "last_name": "User",
                    "role": "admin",
                    "inactivated_at": None,
                },
            ),
        ):
            exit_code = main(_make_args())
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "already active" in captured.err


# ============================================================================
# CLI argument parsing
# ============================================================================


class TestCliParsing:
    """Argument parsing works correctly."""

    def test_cli_calls_main(self):
        from cli.reactivate_user import cli

        with (
            patch("cli.reactivate_user.main", return_value=0) as mock_main,
            patch(
                "sys.argv",
                [
                    "reactivate_user",
                    "--subdomain",
                    "acme",
                    "--email",
                    "admin@acme.com",
                ],
            ),
        ):
            exit_code = cli()
            assert exit_code == 0
            mock_main.assert_called_once()
            args = mock_main.call_args[0][0]
            assert args.subdomain == "acme"
            assert args.email == "admin@acme.com"

    def test_missing_required_args_exits(self):
        from cli.reactivate_user import cli

        with patch("sys.argv", ["reactivate_user"]), pytest.raises(SystemExit) as exc:
            cli()
        assert exc.value.code == 2
