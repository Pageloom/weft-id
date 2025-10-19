"""Tests for database module."""

import database
import pytest


def test_unscoped_constant():
    """Test UNSCOPED constant exists and has correct representation."""
    assert database.UNSCOPED is not None
    assert repr(database.UNSCOPED) == "UNSCOPED"


def test_database_pool_operations(test_tenant):
    """Test database pool can be created and closed."""
    # Get pool (should already be initialized)
    pool = database.get_pool()
    assert pool is not None

    # Pool should be open
    assert not pool.closed

    # Test a simple query works
    result = database.fetchone(
        database.UNSCOPED,
        "SELECT :value as test_value",
        {"value": "test"}
    )
    assert result["test_value"] == "test"
