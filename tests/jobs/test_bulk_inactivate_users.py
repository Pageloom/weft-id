"""Tests for the bulk inactivate users job handler."""

from unittest.mock import patch
from uuid import uuid4


def test_handler_registered():
    """Handler is registered with the correct job type."""
    import jobs.bulk_inactivate_users  # noqa: F401
    from jobs.registry import get_handler

    handler = get_handler("bulk_inactivate_users")
    assert handler is not None


def test_inactivates_users_successfully():
    """Handler inactivates users and returns correct counts."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [user1_id, user2_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]
        mock_db.users.is_service_user.return_value = False

        result = handle_bulk_inactivate_users(task)

    assert result["inactivated"] == 2
    assert result["skipped"] == 0
    assert result["errors"] == 0
    assert "2 inactivated" in result["output"]
    assert len(result["details"]) == 2
    assert result["details"][0]["status"] == "inactivated"
    assert result["details"][1]["status"] == "inactivated"


def test_skips_already_inactivated():
    """Handler skips users that are already inactivated."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [user_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "role": "member",
            "is_inactivated": True,
            "first_name": "Test",
            "last_name": "User",
        }

        result = handle_bulk_inactivate_users(task)

    assert result["inactivated"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == 0
    assert result["details"][0]["status"] == "skipped"
    assert "Already inactivated" in result["details"][0]["reason"]


def test_skips_service_users():
    """Handler skips service users."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [user_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "role": "member",
            "is_inactivated": False,
            "first_name": "Test",
            "last_name": "User",
        }
        mock_db.users.is_service_user.return_value = True

        result = handle_bulk_inactivate_users(task)

    assert result["inactivated"] == 0
    assert result["skipped"] == 1
    assert result["errors"] == 0
    assert result["details"][0]["status"] == "skipped"
    assert "Service user" in result["details"][0]["reason"]


def test_skips_last_super_admin():
    """Handler skips the last super admin to prevent lockout."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [user_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": user_id,
            "role": "super_admin",
            "is_inactivated": False,
            "first_name": "Super",
            "last_name": "Admin",
        }
        mock_db.users.is_service_user.return_value = False
        mock_db.users.count_active_super_admins.return_value = 1

        result = handle_bulk_inactivate_users(task)

    assert result["inactivated"] == 0
    assert result["skipped"] == 1
    assert result["details"][0]["status"] == "skipped"
    assert "Last super admin" in result["details"][0]["reason"]


def test_skips_self_inactivation():
    """Handler skips inactivation when user_id matches created_by."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [admin_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = {
            "id": admin_id,
            "role": "admin",
            "is_inactivated": False,
            "first_name": "Admin",
            "last_name": "User",
        }

        result = handle_bulk_inactivate_users(task)

    assert result["inactivated"] == 0
    assert result["skipped"] == 1
    assert result["details"][0]["status"] == "skipped"
    assert "yourself" in result["details"][0]["reason"].lower()


def test_continues_on_user_not_found():
    """Handler continues processing when a user is not found."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    missing_id = str(uuid4())
    valid_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [missing_id, valid_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            None,
            {
                "id": valid_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]
        mock_db.users.is_service_user.return_value = False

        result = handle_bulk_inactivate_users(task)

    assert result["errors"] == 1
    assert result["inactivated"] == 1
    assert result["details"][0]["status"] == "error"
    assert "not found" in result["details"][0]["reason"].lower()
    assert result["details"][1]["status"] == "inactivated"


def test_continues_on_unexpected_error():
    """Handler continues processing after an unexpected database error."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    error_id = str(uuid4())
    valid_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [error_id, valid_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            RuntimeError("db connection lost"),
            {
                "id": valid_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]
        mock_db.users.is_service_user.return_value = False

        result = handle_bulk_inactivate_users(task)

    assert result["errors"] == 1
    assert result["inactivated"] == 1
    assert result["details"][0]["status"] == "error"
    assert "Unexpected error" in result["details"][0]["reason"]
    assert result["details"][1]["status"] == "inactivated"


def test_revokes_tokens():
    """Handler revokes OAuth tokens for each inactivated user."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [user1_id, user2_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]
        mock_db.users.is_service_user.return_value = False

        handle_bulk_inactivate_users(task)

    assert mock_db.oauth2.revoke_all_user_tokens.call_count == 2
    calls = mock_db.oauth2.revoke_all_user_tokens.call_args_list
    assert calls[0].args == (tenant_id, user1_id)
    assert calls[1].args == (tenant_id, user2_id)


def test_logs_audit_events():
    """Handler logs a user_inactivated event for each successful inactivation."""
    from jobs.bulk_inactivate_users import handle_bulk_inactivate_users

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_inactivate_users",
        "payload": {"user_ids": [user1_id, user2_id]},
    }

    with (
        patch("jobs.bulk_inactivate_users.database") as mock_db,
        patch("jobs.bulk_inactivate_users.log_event") as mock_log,
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Test",
                "last_name": "User",
            },
        ]
        mock_db.users.is_service_user.return_value = False

        handle_bulk_inactivate_users(task)

    assert mock_log.call_count == 2

    # First call
    first_call = mock_log.call_args_list[0].kwargs
    assert first_call["event_type"] == "user_inactivated"
    assert first_call["actor_user_id"] == admin_id
    assert first_call["artifact_id"] == user1_id
    assert first_call["artifact_type"] == "user"
    assert first_call["metadata"]["bulk_operation"] is True

    # Second call
    second_call = mock_log.call_args_list[1].kwargs
    assert second_call["artifact_id"] == user2_id
