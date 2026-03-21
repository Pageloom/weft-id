"""Tests for the email deliverability verification CLI."""

import argparse
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_args(**overrides):
    """Build a Namespace with valid defaults, applying overrides."""
    defaults = {"to": "test@example.com"}
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _txt_rrset(texts: list[str]):
    """Build a fake dns.resolver answer from a list of decoded strings."""
    records = []
    for text in texts:
        rdata = MagicMock()
        rdata.strings = [text.encode()]
        records.append(rdata)
    return records


# ============================================================================
# Domain extraction
# ============================================================================


class TestDomainFromEmail:
    def test_simple_domain(self):
        from cli.verify_email import _domain_from_email

        assert _domain_from_email("user@example.com") == "example.com"

    def test_subdomain(self):
        from cli.verify_email import _domain_from_email

        assert _domain_from_email("user@mail.example.com") == "mail.example.com"

    def test_no_at_sign(self):
        from cli.verify_email import _domain_from_email

        # Degenerate case: returns the whole string
        assert _domain_from_email("nodomain") == "nodomain"


# ============================================================================
# SPF checks
# ============================================================================


class TestCheckSPF:
    def test_pass_when_spf_record_exists(self):
        from cli.verify_email import check_spf

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = ["v=spf1 include:_spf.google.com ~all"]
            status, msg, record = check_spf("example.com")

        assert status == "PASS"
        assert record == "v=spf1 include:_spf.google.com ~all"

    def test_missing_when_no_spf(self):
        from cli.verify_email import check_spf

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = []
            status, msg, record = check_spf("example.com")

        assert status == "MISSING"
        assert record is None

    def test_ignores_non_spf_txt_records(self):
        from cli.verify_email import check_spf

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = [
                "google-site-verification=abc123",
                "some-other-txt-record",
            ]
            status, _msg, record = check_spf("example.com")

        assert status == "MISSING"
        assert record is None

    def test_picks_spf_among_multiple_txt(self):
        from cli.verify_email import check_spf

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = [
                "google-site-verification=abc123",
                "v=spf1 include:sendgrid.net ~all",
            ]
            status, _msg, record = check_spf("example.com")

        assert status == "PASS"
        assert "sendgrid" in record


# ============================================================================
# DMARC checks
# ============================================================================


class TestCheckDMARC:
    def test_pass_with_reject_policy(self):
        from cli.verify_email import check_dmarc

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
            status, msg, record = check_dmarc("example.com")

        assert status == "PASS"
        assert "reject" in msg
        mock.assert_called_once_with("_dmarc.example.com")

    def test_pass_with_quarantine_policy(self):
        from cli.verify_email import check_dmarc

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = ["v=DMARC1; p=quarantine"]
            status, msg, _record = check_dmarc("example.com")

        assert status == "PASS"
        assert "quarantine" in msg

    def test_warn_with_none_policy(self):
        from cli.verify_email import check_dmarc

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = ["v=DMARC1; p=none"]
            status, msg, record = check_dmarc("example.com")

        assert status == "WARN"
        assert "none" in msg.lower()
        assert record is not None

    def test_missing_when_no_record(self):
        from cli.verify_email import check_dmarc

        with patch("cli.verify_email._resolve_txt") as mock:
            mock.return_value = []
            status, _msg, record = check_dmarc("example.com")

        assert status == "MISSING"
        assert record is None


# ============================================================================
# DKIM checks
# ============================================================================


class TestCheckDKIM:
    def test_pass_when_selector_found_sendgrid(self):
        from cli.verify_email import check_dkim

        def fake_resolve(name):
            if name == "s1._domainkey.example.com":
                return ["v=DKIM1; k=rsa; p=MIGfMA0..."]
            return []

        with patch("cli.verify_email._resolve_txt", side_effect=fake_resolve):
            status, msg, found = check_dkim("example.com", "sendgrid")

        assert status == "PASS"
        assert "s1" in found

    def test_pass_when_multiple_selectors_found(self):
        from cli.verify_email import check_dkim

        def fake_resolve(name):
            if "s1._domainkey" in name or "s2._domainkey" in name:
                return ["v=DKIM1; k=rsa; p=MIGfMA0..."]
            return []

        with patch("cli.verify_email._resolve_txt", side_effect=fake_resolve):
            status, msg, found = check_dkim("example.com", "sendgrid")

        assert status == "PASS"
        assert "s1" in found
        assert "s2" in found

    def test_warn_when_no_selectors_found(self):
        from cli.verify_email import check_dkim

        with patch("cli.verify_email._resolve_txt", return_value=[]):
            status, msg, found = check_dkim("example.com", "sendgrid")

        assert status == "WARN"
        assert found == []

    def test_uses_smtp_selectors_for_unknown_backend(self):
        from cli.verify_email import check_dkim

        calls = []

        def fake_resolve(name):
            calls.append(name)
            return []

        with patch("cli.verify_email._resolve_txt", side_effect=fake_resolve):
            check_dkim("example.com", "custom_backend")

        # Should use the smtp selector list for unknown backends
        assert any("default._domainkey" in c for c in calls)
        assert any("selector1._domainkey" in c for c in calls)

    def test_resend_selectors(self):
        from cli.verify_email import check_dkim

        def fake_resolve(name):
            if "resend._domainkey" in name:
                return ["v=DKIM1; k=rsa; p=ABC"]
            return []

        with patch("cli.verify_email._resolve_txt", side_effect=fake_resolve):
            status, _msg, found = check_dkim("example.com", "resend")

        assert status == "PASS"
        assert "resend" in found


# ============================================================================
# DNS resolution helper
# ============================================================================


class TestResolveTxt:
    def test_returns_decoded_strings(self):
        from cli.verify_email import _resolve_txt

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=spf1 ", b"include:example.com ~all"]
        mock_answer = [mock_rdata]

        with patch("cli.verify_email.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.return_value = mock_answer
            result = _resolve_txt("example.com")

        assert result == ["v=spf1 include:example.com ~all"]

    def test_returns_empty_on_nxdomain(self):
        from cli.verify_email import _resolve_txt

        with patch("cli.verify_email.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
            result = _resolve_txt("nonexistent.example.com")

        assert result == []

    def test_returns_empty_on_no_answer(self):
        from cli.verify_email import _resolve_txt

        with patch("cli.verify_email.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
            result = _resolve_txt("example.com")

        assert result == []

    def test_returns_empty_on_timeout(self):
        from cli.verify_email import _resolve_txt

        with patch("cli.verify_email.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.exception.Timeout()
            result = _resolve_txt("example.com")

        assert result == []

    def test_returns_empty_on_no_nameservers(self):
        from cli.verify_email import _resolve_txt

        with patch("cli.verify_email.dns.resolver.Resolver") as mock_cls:
            mock_resolver = MagicMock()
            mock_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
            result = _resolve_txt("example.com")

        assert result == []


# ============================================================================
# Send test email
# ============================================================================


class TestSendTestEmail:
    def test_success_smtp(self, mocker):
        from cli.verify_email import send_test_email

        mocker.patch("settings.EMAIL_BACKEND", "smtp")
        mocker.patch("settings.SMTP_HOST", "smtp.example.com")
        mocker.patch("settings.SMTP_PORT", 587)
        mocker.patch("settings.SMTP_TLS", True)

        mock_backend = MagicMock()
        mock_backend.send.return_value = True
        mocker.patch("utils.email_backends.get_backend", return_value=mock_backend)

        ok, detail = send_test_email("test@example.com")

        assert ok is True
        assert "smtp" in detail
        assert "smtp.example.com:587" in detail
        assert "STARTTLS" in detail
        mock_backend.send.assert_called_once()

    def test_success_smtp_plain(self, mocker):
        from cli.verify_email import send_test_email

        mocker.patch("settings.EMAIL_BACKEND", "smtp")
        mocker.patch("settings.SMTP_HOST", "localhost")
        mocker.patch("settings.SMTP_PORT", 25)
        mocker.patch("settings.SMTP_TLS", False)

        mock_backend = MagicMock()
        mock_backend.send.return_value = True
        mocker.patch("utils.email_backends.get_backend", return_value=mock_backend)

        ok, detail = send_test_email("test@example.com")

        assert ok is True
        assert "plain" in detail

    def test_success_sendgrid(self, mocker):
        from cli.verify_email import send_test_email

        mocker.patch("settings.EMAIL_BACKEND", "sendgrid")

        mock_backend = MagicMock()
        mock_backend.send.return_value = True
        mocker.patch("utils.email_backends.get_backend", return_value=mock_backend)

        ok, detail = send_test_email("test@example.com")

        assert ok is True
        assert "sendgrid" in detail

    def test_success_resend(self, mocker):
        from cli.verify_email import send_test_email

        mocker.patch("settings.EMAIL_BACKEND", "resend")

        mock_backend = MagicMock()
        mock_backend.send.return_value = True
        mocker.patch("utils.email_backends.get_backend", return_value=mock_backend)

        ok, detail = send_test_email("test@example.com")

        assert ok is True
        assert "resend" in detail

    def test_backend_returns_false(self, mocker):
        from cli.verify_email import send_test_email

        mocker.patch("settings.EMAIL_BACKEND", "smtp")

        mock_backend = MagicMock()
        mock_backend.send.return_value = False
        mocker.patch("utils.email_backends.get_backend", return_value=mock_backend)

        ok, detail = send_test_email("test@example.com")

        assert ok is False
        assert "failure" in detail.lower()

    def test_backend_raises_exception(self, mocker):
        from cli.verify_email import send_test_email

        mocker.patch("settings.EMAIL_BACKEND", "smtp")

        mock_backend = MagicMock()
        mock_backend.send.side_effect = ConnectionRefusedError("Connection refused")
        mocker.patch("utils.email_backends.get_backend", return_value=mock_backend)

        ok, detail = send_test_email("test@example.com")

        assert ok is False
        assert "Connection refused" in detail


# ============================================================================
# Main (integration of checks + send)
# ============================================================================


class TestMain:
    def _patch_all(self, mocker, email_ok=True):
        """Patch DNS checks and email send for main() tests."""
        mocker.patch("settings.FROM_EMAIL", "no-reply@example.com")
        mocker.patch("settings.EMAIL_BACKEND", "smtp")
        mocker.patch(
            "cli.verify_email.check_spf",
            return_value=("PASS", "SPF record found", "v=spf1 ~all"),
        )
        mocker.patch(
            "cli.verify_email.check_dmarc",
            return_value=("PASS", "DMARC record found (policy: reject)", "v=DMARC1; p=reject"),
        )
        mocker.patch(
            "cli.verify_email.check_dkim",
            return_value=("PASS", "DKIM found for s1", ["s1"]),
        )
        mocker.patch(
            "cli.verify_email.send_test_email",
            return_value=(email_ok, "Test email sent via smtp"),
        )

    def test_exit_0_all_pass(self, mocker, capsys):
        from cli.verify_email import main

        self._patch_all(mocker, email_ok=True)
        result = main(_make_args())

        assert result == 0
        output = capsys.readouterr().out
        assert "Email sent successfully" in output
        assert "All DNS checks passed" in output

    def test_exit_1_email_failed(self, mocker, capsys):
        from cli.verify_email import main

        self._patch_all(mocker, email_ok=False)
        mocker.patch(
            "cli.verify_email.send_test_email",
            return_value=(False, "smtp backend returned failure"),
        )
        result = main(_make_args())

        assert result == 1
        output = capsys.readouterr().out
        assert "Email delivery failed" in output

    def test_exit_0_with_warnings(self, mocker, capsys):
        from cli.verify_email import main

        self._patch_all(mocker, email_ok=True)
        mocker.patch(
            "cli.verify_email.check_dkim",
            return_value=("WARN", "No DKIM records found", []),
        )
        result = main(_make_args())

        assert result == 0
        output = capsys.readouterr().out
        assert "Email sent successfully" in output
        assert "1 warning" in output

    def test_exit_0_with_missing(self, mocker, capsys):
        from cli.verify_email import main

        self._patch_all(mocker, email_ok=True)
        mocker.patch(
            "cli.verify_email.check_spf",
            return_value=("MISSING", "No SPF record", None),
        )
        result = main(_make_args())

        assert result == 0
        output = capsys.readouterr().out
        assert "1 missing record" in output

    def test_exit_1_with_missing_and_failed_email(self, mocker, capsys):
        from cli.verify_email import main

        self._patch_all(mocker, email_ok=False)
        mocker.patch(
            "cli.verify_email.send_test_email",
            return_value=(False, "Connection refused"),
        )
        mocker.patch(
            "cli.verify_email.check_spf",
            return_value=("MISSING", "No SPF record", None),
        )
        mocker.patch(
            "cli.verify_email.check_dmarc",
            return_value=("MISSING", "No DMARC record", None),
        )
        result = main(_make_args())

        assert result == 1
        output = capsys.readouterr().out
        assert "Email delivery failed" in output
        assert "2 missing records" in output


# ============================================================================
# CLI argument parsing
# ============================================================================


class TestCLI:
    def test_valid_email(self, mocker):
        from cli.verify_email import cli

        mocker.patch("sys.argv", ["verify_email", "--to", "test@example.com"])
        mock_main = mocker.patch("cli.verify_email.main", return_value=0)

        result = cli()

        assert result == 0
        mock_main.assert_called_once()

    def test_invalid_email_no_at(self, mocker, capsys):
        from cli.verify_email import cli

        mocker.patch("sys.argv", ["verify_email", "--to", "not-an-email"])

        result = cli()

        assert result == 1
        assert "invalid email" in capsys.readouterr().err.lower()

    def test_missing_to_exits(self, mocker):
        from cli.verify_email import cli

        mocker.patch("sys.argv", ["verify_email"])

        with pytest.raises(SystemExit) as exc_info:
            cli()
        assert exc_info.value.code == 2  # argparse error
