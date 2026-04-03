"""Tests for the bulk reactivate users job handler."""

from unittest.mock import patch
from uuid import uuid4


def test_handler_registered():
    """Handler is registered with the correct job type."""
    import jobs.bulk_reactivate_users  # noqa: F401
    from jobs.registry import get_handler

    handler = get_handler("bulk_reactivate_users")
    assert handler is not None


def test_reactivates_users_successfully():
    """Handler reactivates inactivated users and returns correct counts."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [user1_id, user2_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]

        result = handle_bulk_reactivate_users(task)

    assert result["reactivated"] == 2
    assert result["skipped"] == 0
    assert result["errors"] == 0
    assert "2 reactivated" in result["output"]
    assert len(result["details"]) == 2
    assert result["details"][0]["status"] == "reactivated"
    assert result["details"][1]["status"] == "reactivated"


def test_skips_not_inactivated():
    """Handler skips users that are not inactivated."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [user_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "is_inactivated": False,
            "is_anonymized": False,
            "first_name": "Test",
            "last_name": "User",
        }

        result = handle_bulk_reactivate_users(task)

    assert result["reactivated"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == 0
    assert result["details"][0]["status"] == "skipped"
    assert "Not inactivated" in result["details"][0]["reason"]


def test_skips_anonymized_users():
    """Handler skips anonymized users since anonymization is irreversible."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [user_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "is_inactivated": True,
            "is_anonymized": True,
            "first_name": "[Anonymized]",
            "last_name": "User",
        }

        result = handle_bulk_reactivate_users(task)

    assert result["reactivated"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == 0
    assert result["details"][0]["status"] == "skipped"
    assert "Anonymized" in result["details"][0]["reason"]


def test_clears_reactivation_denied():
    """Handler clears reactivation_denied flag for each reactivated user."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [user1_id, user2_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]

        handle_bulk_reactivate_users(task)

    assert mock_db.users.clear_reactivation_denied.call_count == 2
    calls = mock_db.users.clear_reactivation_denied.call_args_list
    assert calls[0].args == (tenant_id, user1_id)
    assert calls[1].args == (tenant_id, user2_id)


def test_continues_on_user_not_found():
    """Handler continues processing when a user is not found."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    missing_id = str(uuid4())
    valid_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [missing_id, valid_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            None,
            {
                "id": valid_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]

        result = handle_bulk_reactivate_users(task)

    assert result["errors"] == 1
    assert result["reactivated"] == 1
    assert result["details"][0]["status"] == "error"
    assert "not found" in result["details"][0]["reason"].lower()
    assert result["details"][1]["status"] == "reactivated"


def test_continues_on_unexpected_error():
    """Handler continues processing after an unexpected database error."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    error_id = str(uuid4())
    valid_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [error_id, valid_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            RuntimeError("db connection lost"),
            {
                "id": valid_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]

        result = handle_bulk_reactivate_users(task)

    assert result["errors"] == 1
    assert result["reactivated"] == 1
    assert result["details"][0]["status"] == "error"
    assert "Unexpected error" in result["details"][0]["reason"]
    assert result["details"][1]["status"] == "reactivated"


def test_logs_audit_events():
    """Handler logs a user_reactivated event for each successful reactivation."""
    from jobs.bulk_reactivate_users import handle_bulk_reactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_reactivate_users",
        "payload": {"user_ids": [user1_id, user2_id]},
    }

    with (
        patch("jobs.bulk_reactivate_users.database") as mock_db,
        patch("jobs.bulk_reactivate_users.log_event") as mock_log,
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]

        handle_bulk_reactivate_users(task)

    assert mock_log.call_count == 2

    # First call
    first_call = mock_log.call_args_list[0].kwargs
    assert first_call["event_type"] == "user_reactivated"
    assert first_call["actor_user_id"] == admin_id
    assert first_call["artifact_id"] == user1_id
    assert first_call["artifact_type"] == "user"
    assert first_call["metadata"]["bulk_operation"] is True

    # Second call
    second_call = mock_log.call_args_list[1].kwargs
    assert second_call["artifact_id"] == user2_id
