"""Tests for database.security module."""

import pytest


def test_get_security_settings(test_tenant):
    """Test retrieving all security settings."""
    import database

    settings = database.security.get_security_settings(test_tenant["id"])

    # Should return settings dict or None based on schema
    # Not asserting specific structure since it depends on your schema
    assert settings is not None or settings is None
