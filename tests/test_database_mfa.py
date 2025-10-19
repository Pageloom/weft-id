"""Tests for database.mfa module."""

import pytest


def test_set_mfa_method(test_user):
    """Test setting MFA method for a user."""
    import database

    # Set MFA method to email (default)
    database.mfa.set_mfa_method(
        test_user["tenant_id"],
        test_user["id"],
        "email"
    )

    # Verify it was set by checking user record
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["mfa_method"] == "email"
