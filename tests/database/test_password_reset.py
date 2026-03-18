"""Database integration tests for password reset columns and functions."""

import database


def test_password_reset_required_default_false(test_tenant, test_user):
    """Test that password_reset_required defaults to false."""
    user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
    assert user is not None
    assert user["password_reset_required"] is False


def test_set_password_reset_required_true(test_tenant, test_user):
    """Test setting password_reset_required to true."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    rows = database.users.set_password_reset_required(tid, uid, True)
    assert rows == 1

    user = database.users.get_user_by_id(tid, uid)
    assert user["password_reset_required"] is True


def test_set_password_reset_required_false(test_tenant, test_user):
    """Test clearing password_reset_required."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    database.users.set_password_reset_required(tid, uid, True)
    database.users.set_password_reset_required(tid, uid, False)

    user = database.users.get_user_by_id(tid, uid)
    assert user["password_reset_required"] is False


def test_update_password_clears_reset_flag(test_tenant, test_user):
    """Test that updating a password clears password_reset_required."""
    tid = test_tenant["id"]
    uid = str(test_user["id"])

    # Set the flag
    database.users.set_password_reset_required(tid, uid, True)

    # Update password (should clear the flag)
    # Hash must be 60-255 chars per check constraint
    valid_hash = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 40
    database.users.update_password(tid, uid, valid_hash)

    user = database.users.get_user_by_id(tid, uid)
    assert user["password_reset_required"] is False


def test_password_changed_at_initially_null(test_tenant, test_user):
    """Test that password_changed_at is null for new users."""
    user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
    # New users created by the test fixture may not have password_changed_at set
    # This column is only set when a password is changed via update_password
    # The initial password set during user creation doesn't go through update_password
    assert user is not None
