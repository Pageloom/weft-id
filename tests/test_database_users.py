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
