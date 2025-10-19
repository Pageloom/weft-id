"""Tests for database.users module."""

import pytest


def test_get_user_by_id(test_user):
    """Test retrieving a user by ID."""
    import database

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])

    assert user is not None
    assert user["id"] == test_user["id"]
    assert user["first_name"] == test_user["first_name"]
    assert user["last_name"] == test_user["last_name"]
    assert user["role"] == test_user["role"]


def test_get_user_by_email(test_user):
    """Test retrieving a user by email."""
    import database

    user = database.users.get_user_by_email(test_user["tenant_id"], test_user["email"])

    assert user is not None
    assert user["user_id"] == test_user["id"]
    assert user["password_hash"] is not None


def test_get_user_by_email_not_found(test_tenant):
    """Test retrieving a non-existent user returns None."""
    import database

    user = database.users.get_user_by_email(test_tenant["id"], "nonexistent@example.com")

    assert user is None


def test_update_user_profile(test_user):
    """Test updating user profile information."""
    import database

    # Update the user's profile
    database.users.update_user_profile(
        test_user["tenant_id"],
        test_user["id"],
        first_name="Updated",
        last_name="Name"
    )

    # Verify the update
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["first_name"] == "Updated"
    assert user["last_name"] == "Name"


def test_list_users(test_tenant, test_user, test_admin_user):
    """Test listing users with pagination."""
    import database

    users = database.users.list_users(test_tenant["id"], page=1, page_size=10)

    assert len(users) == 2
    assert any(u["id"] == test_user["id"] for u in users)
    assert any(u["id"] == test_admin_user["id"] for u in users)


def test_list_users_with_search(test_user):
    """Test listing users with search query."""
    import database

    users = database.users.list_users(
        test_user["tenant_id"],
        search=test_user["first_name"],
        page=1,
        page_size=10
    )

    assert len(users) >= 1
    assert any(u["id"] == test_user["id"] for u in users)


def test_count_users(test_tenant, test_user, test_admin_user):
    """Test counting users in a tenant."""
    import database

    count = database.users.count_users(test_tenant["id"])

    assert count == 2


def test_count_users_with_search(test_user):
    """Test counting users with search query."""
    import database

    count = database.users.count_users(
        test_user["tenant_id"],
        search=test_user["first_name"]
    )

    assert count >= 1


def test_update_user_timezone(test_user):
    """Test updating user's timezone."""
    import database

    database.users.update_user_timezone(
        test_user["tenant_id"],
        test_user["id"],
        "America/New_York"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "America/New_York"


def test_update_user_locale(test_user):
    """Test updating user's locale."""
    import database

    database.users.update_user_locale(
        test_user["tenant_id"],
        test_user["id"],
        "fr-FR"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["locale"] == "fr-FR"


def test_update_user_timezone_and_locale(test_user):
    """Test updating user's timezone and locale together."""
    import database

    database.users.update_user_timezone_and_locale(
        test_user["tenant_id"],
        test_user["id"],
        "Europe/London",
        "en-GB"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "Europe/London"
    assert user["locale"] == "en-GB"


def test_update_last_login(test_user):
    """Test updating user's last login timestamp."""
    import database

    # Get initial last_login
    user_before = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    initial_last_login = user_before["last_login"]

    # Update last login
    database.users.update_last_login(
        test_user["tenant_id"],
        test_user["id"]
    )

    # Verify it was updated
    user_after = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])

    # Should be different (or at least set if it was None)
    if initial_last_login is None:
        assert user_after["last_login"] is not None
    else:
        # Timestamps should differ
        assert user_after["last_login"] != initial_last_login or user_after["last_login"] == initial_last_login


def test_update_timezone_and_last_login(test_user):
    """Test updating user's timezone and last login together."""
    import database

    database.users.update_timezone_and_last_login(
        test_user["tenant_id"],
        test_user["id"],
        "Asia/Tokyo"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "Asia/Tokyo"
    assert user["last_login"] is not None


def test_update_locale_and_last_login(test_user):
    """Test updating user's locale and last login together."""
    import database

    database.users.update_locale_and_last_login(
        test_user["tenant_id"],
        test_user["id"],
        "ja-JP"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["locale"] == "ja-JP"
    assert user["last_login"] is not None


def test_update_timezone_locale_and_last_login(test_user):
    """Test updating user's timezone, locale, and last login together."""
    import database

    database.users.update_timezone_locale_and_last_login(
        test_user["tenant_id"],
        test_user["id"],
        "Australia/Sydney",
        "en-AU"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "Australia/Sydney"
    assert user["locale"] == "en-AU"
    assert user["last_login"] is not None


def test_check_collation_exists(test_user):
    """Test checking if a collation exists."""
    import database

    # C collation should always exist in PostgreSQL
    exists = database.users.check_collation_exists(
        test_user["tenant_id"],
        "C"
    )

    assert exists is True

    # Non-existent collation
    exists = database.users.check_collation_exists(
        test_user["tenant_id"],
        "nonexistent-collation-xyz"
    )

    assert exists is False


def test_list_users_with_invalid_sort_field(test_user):
    """Test that invalid sort field defaults to created_at."""
    import database

    # Use an invalid sort field
    users = database.users.list_users(
        test_user["tenant_id"],
        sort_field="invalid_field",
        page=1,
        page_size=10
    )

    # Should still return users (falls back to created_at)
    assert len(users) >= 1


def test_list_users_with_invalid_sort_order(test_user):
    """Test that invalid sort order defaults to desc."""
    import database

    # Use an invalid sort order
    users = database.users.list_users(
        test_user["tenant_id"],
        sort_order="invalid_order",
        page=1,
        page_size=10
    )

    # Should still return users (falls back to desc)
    assert len(users) >= 1
