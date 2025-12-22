"""Tests for database.user_activity module."""

from time import sleep


def test_upsert_activity_creates_new_record(test_tenant, test_user):
    """Test that upsert_activity creates a new record when none exists."""
    import database

    # Ensure no existing record
    initial = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert initial is None

    # Upsert activity
    rows_affected = database.user_activity.upsert_activity(test_tenant["id"], str(test_user["id"]))

    assert rows_affected == 1

    # Verify record was created
    activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity is not None
    assert str(activity["user_id"]) == str(test_user["id"])
    assert str(activity["tenant_id"]) == str(test_tenant["id"])
    assert activity["last_activity_at"] is not None


def test_upsert_activity_updates_existing_record(test_tenant, test_user):
    """Test that upsert_activity updates an existing record."""
    import database

    # Create initial record
    database.user_activity.upsert_activity(test_tenant["id"], str(test_user["id"]))

    # Get initial timestamp
    activity1 = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    initial_time = activity1["last_activity_at"]

    # Small delay to ensure timestamp difference
    sleep(0.1)

    # Upsert again
    rows_affected = database.user_activity.upsert_activity(test_tenant["id"], str(test_user["id"]))

    assert rows_affected == 1

    # Verify timestamp was updated
    activity2 = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity2["last_activity_at"] >= initial_time


def test_get_activity_returns_none_for_nonexistent_user(test_tenant):
    """Test that get_activity returns None for a user with no activity record."""
    from uuid import uuid4

    import database

    # Use a random UUID that doesn't exist
    fake_user_id = str(uuid4())

    activity = database.user_activity.get_activity(test_tenant["id"], fake_user_id)

    assert activity is None


def test_activity_tenant_isolation(test_tenant, test_user):
    """Test that activity records are tenant-isolated via RLS."""
    from uuid import uuid4

    import database

    # Create activity in test tenant
    database.user_activity.upsert_activity(test_tenant["id"], str(test_user["id"]))

    # Create another tenant
    other_subdomain = f"other-{str(uuid4())[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": other_subdomain, "name": "Other Tenant"},
    )
    other_tenant = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": other_subdomain},
    )

    try:
        # Query from other tenant should not see test tenant's activity
        activity = database.user_activity.get_activity(other_tenant["id"], str(test_user["id"]))
        assert activity is None
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other_tenant["id"]},
        )


def test_activity_deleted_when_user_deleted(test_tenant):
    """Test that activity record is deleted when user is deleted (CASCADE)."""

    import database
    from argon2 import PasswordHasher

    ph = PasswordHasher()

    # Create a temporary user
    temp_user = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :password_hash, 'Temp', 'User', 'member')
        RETURNING id
        """,
        {
            "tenant_id": test_tenant["id"],
            "password_hash": ph.hash("TempPassword123!"),
        },
    )

    # Create activity for temp user
    database.user_activity.upsert_activity(test_tenant["id"], str(temp_user["id"]))

    # Verify activity exists
    activity = database.user_activity.get_activity(test_tenant["id"], str(temp_user["id"]))
    assert activity is not None

    # Delete the user
    database.execute(
        test_tenant["id"],
        "DELETE FROM users WHERE id = :user_id",
        {"user_id": temp_user["id"]},
    )

    # Verify activity was deleted via CASCADE
    activity_after = database.user_activity.get_activity(test_tenant["id"], str(temp_user["id"]))
    assert activity_after is None
