"""Tests for the admin notification side of the idle-user inactivation job.

Covers the best-effort `_notify_admins_of_inactivation` helper and the
wiring from `_process_tenant` to it.
"""

from datetime import UTC, datetime
from unittest.mock import patch

from jobs import inactivate_idle_users as job


def _users(n: int = 1) -> list[dict]:
    base = [
        {
            "user_id": "u1",
            "first_name": "Alice",
            "last_name": "Smith",
            "email": "alice@example.com",
            "last_activity_at": datetime(2024, 1, 15, tzinfo=UTC),
        },
        {
            "user_id": "u2",
            "first_name": "Bob",
            "last_name": "Jones",
            "email": "bob@example.com",
            "last_activity_at": datetime(2024, 2, 20, tzinfo=UTC),
        },
    ]
    return base[:n]


@patch("jobs.inactivate_idle_users.send_idle_users_inactivation_admin_notification")
@patch("jobs.inactivate_idle_users.database")
def test_notify_sends_one_email_per_admin(mock_db, mock_send):
    mock_db.users.get_admin_emails.return_value = ["a@x.com", "b@x.com"]
    users = _users(2)

    job._notify_admins_of_inactivation("tenant-1", users, 90)

    assert mock_send.call_count == 2
    first = mock_send.call_args_list[0]
    assert first.kwargs["to_email"] == "a@x.com"
    assert first.kwargs["inactivated_users"] == users
    assert first.kwargs["threshold_days"] == 90
    assert first.kwargs["tenant_id"] == "tenant-1"


@patch("jobs.inactivate_idle_users.send_idle_users_inactivation_admin_notification")
@patch("jobs.inactivate_idle_users.database")
def test_notify_skips_when_no_inactivated_users(mock_db, mock_send):
    job._notify_admins_of_inactivation("tenant-1", [], 90)

    mock_db.users.get_admin_emails.assert_not_called()
    mock_send.assert_not_called()


@patch("jobs.inactivate_idle_users.send_idle_users_inactivation_admin_notification")
@patch("jobs.inactivate_idle_users.database")
def test_notify_no_admins_sends_nothing(mock_db, mock_send):
    mock_db.users.get_admin_emails.return_value = []

    job._notify_admins_of_inactivation("tenant-1", _users(1), 90)

    mock_send.assert_not_called()


@patch("jobs.inactivate_idle_users.send_idle_users_inactivation_admin_notification")
@patch("jobs.inactivate_idle_users.database")
def test_notify_swallows_per_send_errors(mock_db, mock_send):
    mock_db.users.get_admin_emails.return_value = ["a@x.com", "b@x.com"]
    mock_send.side_effect = [RuntimeError("smtp down"), None]

    # One failing address must not stop the other or raise.
    job._notify_admins_of_inactivation("tenant-1", _users(1), 90)

    assert mock_send.call_count == 2


@patch("jobs.inactivate_idle_users.send_idle_users_inactivation_admin_notification")
@patch("jobs.inactivate_idle_users.database")
def test_notify_swallows_admin_lookup_error(mock_db, mock_send):
    mock_db.users.get_admin_emails.side_effect = RuntimeError("db down")

    # Lookup failure must not abort the job.
    job._notify_admins_of_inactivation("tenant-1", _users(1), 90)

    mock_send.assert_not_called()


@patch("jobs.inactivate_idle_users._notify_admins_of_inactivation")
@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.database")
def test_process_tenant_notifies_with_inactivated_user_dicts(mock_db, mock_log, mock_notify):
    users = _users(2)
    mock_db.users.get_idle_users_for_tenant.return_value = users

    result = job._process_tenant("tenant-1", 90)

    assert result["count"] == 2
    mock_notify.assert_called_once()
    args = mock_notify.call_args.args
    assert args[0] == "tenant-1"
    # The full user dicts (not just ids) are handed to the notifier.
    assert args[1] == users
    assert args[2] == 90


@patch("jobs.inactivate_idle_users._notify_admins_of_inactivation")
@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.database")
def test_process_tenant_no_idle_users_skips_notify(mock_db, mock_log, mock_notify):
    mock_db.users.get_idle_users_for_tenant.return_value = []

    result = job._process_tenant("tenant-1", 90)

    assert result["count"] == 0
    mock_notify.assert_not_called()
