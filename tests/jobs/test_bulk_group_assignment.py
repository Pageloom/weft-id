"""Tests for the bulk group assignment job handler."""

from unittest.mock import patch
from uuid import uuid4


def test_handler_registered():
    """Handler is registered with the correct job type."""
    import jobs.bulk_group_assignment  # noqa: F401
    from jobs.registry import get_handler

    handler = get_handler("bulk_group_assignment")
    assert handler is not None


def _make_task(tenant_id, admin_id, group_id, user_ids):
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "created_by": admin_id,
        "job_type": "bulk_group_assignment",
        "payload": {"group_id": group_id, "user_ids": user_ids},
    }


def _make_user(user_id, first_name="Test", last_name="User"):
    return {
        "id": user_id,
        "first_name": first_name,
        "last_name": last_name,
        "role": "member",
    }


def test_adds_users_successfully():
    """Handler adds users to the group and returns correct counts."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [user1_id, user2_id])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event") as mock_log,
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Engineering",
            "group_type": "weftid",
        }
        mock_db.users.get_user_by_id.side_effect = [
            _make_user(user1_id, "Alice", "Smith"),
            _make_user(user2_id, "Bob", "Jones"),
        ]
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 2
    assert result["skipped"] == 0
    assert result["errors"] == 0
    assert "2 added" in result["output"]
    assert len(result["details"]) == 2
    assert result["details"][0]["status"] == "added"
    assert result["details"][1]["status"] == "added"
    assert mock_log.call_count == 2
    # Verify bulk_operation metadata
    call_kwargs = mock_log.call_args_list[0].kwargs
    assert call_kwargs["event_type"] == "group_member_added"
    assert call_kwargs["metadata"]["bulk_operation"] is True


def test_skips_already_member():
    """Handler skips users already in the group."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [user_id])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Engineering",
            "group_type": "weftid",
        }
        mock_db.users.get_user_by_id.return_value = _make_user(user_id)
        mock_db.groups.is_group_member.return_value = True

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 0
    assert result["skipped"] == 1
    assert result["details"][0]["status"] == "skipped"
    assert result["details"][0]["reason"] == "Already a member"


def test_skips_user_not_found():
    """Handler skips users that don't exist."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [user_id])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Engineering",
            "group_type": "weftid",
        }
        mock_db.users.get_user_by_id.return_value = None

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 0
    assert result["skipped"] == 1
    assert result["details"][0]["status"] == "skipped"
    assert result["details"][0]["reason"] == "User not found"


def test_rejects_idp_group():
    """Handler rejects IdP groups entirely."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [user_id])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Okta Group",
            "group_type": "idp",
        }

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 0
    assert result["errors"] == 1
    assert "IdP groups cannot be modified" in result["output"]


def test_group_not_found():
    """Handler returns error when group doesn't exist."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user_id = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [user_id])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 0
    assert result["errors"] == 1
    assert "Group not found" in result["output"]


def test_handles_unexpected_error():
    """Handler catches exceptions per user and continues."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [user1_id, user2_id])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Engineering",
            "group_type": "weftid",
        }
        # First user raises, second succeeds
        mock_db.users.get_user_by_id.side_effect = [
            RuntimeError("DB error"),
            _make_user(user2_id, "Bob", "Jones"),
        ]
        mock_db.groups.is_group_member.return_value = False
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 1
    assert result["errors"] == 1
    assert result["details"][0]["status"] == "error"
    assert result["details"][1]["status"] == "added"


def test_mixed_results():
    """Handler handles a mix of added, skipped, and errored users."""
    from jobs.bulk_group_assignment import handle_bulk_group_assignment

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    uid_new = str(uuid4())
    uid_member = str(uuid4())
    uid_missing = str(uuid4())

    task = _make_task(tenant_id, admin_id, group_id, [uid_new, uid_member, uid_missing])

    with (
        patch("jobs.bulk_group_assignment.database") as mock_db,
        patch("jobs.bulk_group_assignment.log_event"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Engineering",
            "group_type": "weftid",
        }
        mock_db.users.get_user_by_id.side_effect = [
            _make_user(uid_new, "Alice", "New"),
            _make_user(uid_member, "Bob", "Member"),
            None,  # missing
        ]
        mock_db.groups.is_group_member.side_effect = [False, True]
        mock_db.groups.add_group_member.return_value = {"id": str(uuid4())}

        result = handle_bulk_group_assignment(task)

    assert result["added"] == 1
    assert result["skipped"] == 2
    assert result["errors"] == 0
    assert result["output"] == "1 added, 2 skipped, 0 errors"
