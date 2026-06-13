"""Tests for the idle-user inactivation admin summary email."""

from datetime import UTC, datetime
from unittest.mock import patch

from utils.email import send_idle_users_inactivation_admin_notification


def _users(n: int = 2) -> list[dict]:
    base = [
        {
            "first_name": "Alice",
            "last_name": "Smith",
            "email": "alice@example.com",
            "last_activity_at": datetime(2024, 1, 15, tzinfo=UTC),
        },
        {
            "first_name": "Bob",
            "last_name": "Jones",
            "email": "bob@example.com",
            "last_activity_at": datetime(2024, 2, 20, tzinfo=UTC),
        },
    ]
    return base[:n]


def test_lists_users_and_threshold_in_both_bodies():
    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True
        result = send_idle_users_inactivation_admin_notification("admin@example.com", _users(2), 90)

    assert result is True
    mock_send.assert_called_once()
    to_email, subject, html_body, text_body = mock_send.call_args.args
    assert to_email == "admin@example.com"
    assert subject == "WeftID: 2 users deactivated due to inactivity"
    for body in (html_body, text_body):
        assert "Alice Smith" in body
        assert "alice@example.com" in body
        assert "2024-01-15" in body
        assert "bob@example.com" in body
        assert "2024-02-20" in body
        assert "90 days" in body


def test_singular_subject():
    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True
        send_idle_users_inactivation_admin_notification("admin@example.com", _users(1), 30)

    subject = mock_send.call_args.args[1]
    assert subject == "WeftID: 1 user deactivated due to inactivity"


def test_handles_missing_last_activity_and_name():
    users = [
        {
            "first_name": None,
            "last_name": None,
            "email": "x@example.com",
            "last_activity_at": None,
        }
    ]
    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True
        send_idle_users_inactivation_admin_notification("admin@example.com", users, 90)

    text_body = mock_send.call_args.args[3]
    assert "never active" in text_body
    assert "x@example.com" in text_body


def test_returns_false_on_send_failure():
    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False
        result = send_idle_users_inactivation_admin_notification("admin@example.com", _users(1), 90)

    assert result is False
