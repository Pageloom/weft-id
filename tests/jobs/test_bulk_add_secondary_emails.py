"""Tests for the bulk add secondary emails job handler."""

from unittest.mock import patch
from uuid import uuid4


def test_handler_registered():
    """Handler is registered with the correct job type."""
    import jobs.bulk_add_secondary_emails  # noqa: F401
    from jobs.registry import get_handler

    handler = get_handler("bulk_add_secondary_emails")
    assert handler is not None


def test_handler_adds_emails_successfully():
    """Handler adds verified emails and returns correct counts."""
    from jobs.bulk_add_secondary_emails import handle_bulk_add_secondary_emails

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_add_secondary_emails",
        "payload": {
            "items": [
                {"user_id": user1_id, "email": "New1@Example.com"},
                {"user_id": user2_id, "email": "new2@example.com"},
            ]
        },
    }

    with (
        patch("jobs.bulk_add_secondary_emails.database") as mock_db,
        patch("jobs.bulk_add_secondary_emails.log_event"),
    ):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.get_user_by_id.return_value = {"id": "some-id"}
        mock_db.user_emails.add_verified_email.return_value = {"id": str(uuid4())}

        result = handle_bulk_add_secondary_emails(task)

    assert result["added"] == 2
    assert result["skipped"] == 0
    assert result["errors"] == 0
    assert "2 added" in result["output"]
    assert len(result["details"]) == 2
    assert result["details"][0]["status"] == "added"

    # Verify emails were lowercased
    calls = mock_db.user_emails.add_verified_email.call_args_list
    assert calls[0].kwargs["email"] == "new1@example.com"
    assert calls[1].kwargs["email"] == "new2@example.com"


def test_handler_skips_existing_emails():
    """Handler skips emails that already exist in the tenant."""
    from jobs.bulk_add_secondary_emails import handle_bulk_add_secondary_emails

    tenant_id = str(uuid4())
    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": str(uuid4()),
        "job_type": "bulk_add_secondary_emails",
        "payload": {
            "items": [
                {"user_id": str(uuid4()), "email": "existing@example.com"},
            ]
        },
    }

    with (
        patch("jobs.bulk_add_secondary_emails.database") as mock_db,
        patch("jobs.bulk_add_secondary_emails.log_event"),
    ):
        mock_db.user_emails.email_exists.return_value = True

        result = handle_bulk_add_secondary_emails(task)

    assert result["added"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == 0
    assert result["details"][0]["status"] == "skipped"
    assert "already exists" in result["details"][0]["reason"]


def test_handler_errors_on_missing_user():
    """Handler reports error for non-existent users."""
    from jobs.bulk_add_secondary_emails import handle_bulk_add_secondary_emails

    task = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "created_by": str(uuid4()),
        "job_type": "bulk_add_secondary_emails",
        "payload": {
            "items": [
                {"user_id": str(uuid4()), "email": "new@example.com"},
            ]
        },
    }

    with (
        patch("jobs.bulk_add_secondary_emails.database") as mock_db,
        patch("jobs.bulk_add_secondary_emails.log_event"),
    ):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.get_user_by_id.return_value = None

        result = handle_bulk_add_secondary_emails(task)

    assert result["added"] == 0
    assert result["skipped"] == 0
    assert result["errors"] == 1
    assert result["details"][0]["status"] == "error"
    assert "not found" in result["details"][0]["reason"].lower()


def test_handler_mixed_results():
    """Handler handles a mix of success, skip, and error items."""
    from jobs.bulk_add_secondary_emails import handle_bulk_add_secondary_emails

    tenant_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())
    user3_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": str(uuid4()),
        "job_type": "bulk_add_secondary_emails",
        "payload": {
            "items": [
                {"user_id": user1_id, "email": "new@example.com"},
                {"user_id": user2_id, "email": "existing@example.com"},
                {"user_id": user3_id, "email": "another@example.com"},
            ]
        },
    }

    with (
        patch("jobs.bulk_add_secondary_emails.database") as mock_db,
        patch("jobs.bulk_add_secondary_emails.log_event"),
    ):
        # First email: new, user exists -> success
        # Second email: already exists -> skip
        # Third email: new, user not found -> error
        mock_db.user_emails.email_exists.side_effect = [False, True, False]
        mock_db.users.get_user_by_id.side_effect = [
            {"id": user1_id},
            {"id": user3_id},  # Won't be reached for user2 (skipped)
        ]
        # Only user3 returns None (not found)
        mock_db.users.get_user_by_id.side_effect = [{"id": user1_id}, None]
        mock_db.user_emails.add_verified_email.return_value = {"id": str(uuid4())}

        result = handle_bulk_add_secondary_emails(task)

    assert result["added"] == 1
    assert result["skipped"] == 1
    assert result["errors"] == 1
    assert "1 added, 1 skipped, 1 errors" in result["output"]


def test_handler_logs_event_per_addition():
    """Handler logs an email_added event for each successfully added email."""
    from jobs.bulk_add_secondary_emails import handle_bulk_add_secondary_emails

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_add_secondary_emails",
        "payload": {
            "items": [
                {"user_id": user_id, "email": "new@example.com"},
            ]
        },
    }

    with (
        patch("jobs.bulk_add_secondary_emails.database") as mock_db,
        patch("jobs.bulk_add_secondary_emails.log_event") as mock_log,
    ):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.get_user_by_id.return_value = {"id": user_id}
        mock_db.user_emails.add_verified_email.return_value = {"id": str(uuid4())}

        handle_bulk_add_secondary_emails(task)

    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "email_added"
    assert call_kwargs["actor_user_id"] == admin_id
    assert call_kwargs["artifact_id"] == user_id
    assert call_kwargs["metadata"]["email"] == "new@example.com"
    assert call_kwargs["metadata"]["bulk_operation"] is True


def test_handler_catches_unexpected_errors():
    """Handler continues processing after unexpected errors on individual items."""
    from jobs.bulk_add_secondary_emails import handle_bulk_add_secondary_emails

    task = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "created_by": str(uuid4()),
        "job_type": "bulk_add_secondary_emails",
        "payload": {
            "items": [
                {"user_id": str(uuid4()), "email": "fail@example.com"},
                {"user_id": str(uuid4()), "email": "ok@example.com"},
            ]
        },
    }

    with (
        patch("jobs.bulk_add_secondary_emails.database") as mock_db,
        patch("jobs.bulk_add_secondary_emails.log_event"),
    ):
        mock_db.user_emails.email_exists.return_value = False
        mock_db.users.get_user_by_id.return_value = {"id": "some-id"}
        # First call raises, second succeeds
        mock_db.user_emails.add_verified_email.side_effect = [
            RuntimeError("db error"),
            {"id": str(uuid4())},
        ]

        result = handle_bulk_add_secondary_emails(task)

    assert result["errors"] == 1
    assert result["added"] == 1
    assert result["details"][0]["status"] == "error"
    assert result["details"][1]["status"] == "added"
