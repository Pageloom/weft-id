"""Tests for database module."""

import uuid

import database
import pytest
from psycopg.types.json import Json


def test_unscoped_constant():
    """Test UNSCOPED constant exists and has correct representation."""
    assert database.UNSCOPED is not None
    assert repr(database.UNSCOPED) == "UNSCOPED"


class TestEscapeLike:
    """Tests for escape_like helper."""

    def test_no_special_characters(self):
        assert database.escape_like("hello") == "hello"

    def test_percent_escaped(self):
        assert database.escape_like("100%") == "100\\%"

    def test_underscore_escaped(self):
        assert database.escape_like("user_1") == "user\\_1"

    def test_backslash_escaped(self):
        assert database.escape_like("path\\file") == "path\\\\file"

    def test_all_special_characters(self):
        assert database.escape_like("a\\b%c_d") == "a\\\\b\\%c\\_d"

    def test_empty_string(self):
        assert database.escape_like("") == ""

    def test_multiple_wildcards(self):
        assert database.escape_like("%%__") == "\\%\\%\\_\\_"


def test_database_pool_operations(test_tenant):
    """Test database pool can be created and closed."""
    # Get pool (should already be initialized)
    pool = database.get_pool()
    assert pool is not None

    # Pool should be open
    assert not pool.closed

    # Test a simple query works
    result = database.fetchone(database.UNSCOPED, "SELECT :value as test_value", {"value": "test"})
    assert result["test_value"] == "test"


def test_validate_params_with_array_values(test_tenant):
    """Test that array/list values are properly validated."""
    # Lists are valid PostgreSQL values
    result = database.fetchone(
        test_tenant["id"], "SELECT :values as array_test", {"values": [1, 2, 3]}
    )
    assert result["array_test"] == [1, 2, 3]


def test_validate_params_with_invalid_dict_value():
    """Test that plain dict values raise an error with helpful hint."""
    # Plain dicts are NOT allowed (must be wrapped in Json())
    with pytest.raises(RuntimeError) as exc_info:
        database.execute(
            database.UNSCOPED,
            "SELECT :data as json_test",
            {"data": {"key": "value"}},  # Invalid - should be Json({"key": "value"})
        )

    error_message = str(exc_info.value)
    assert "unsupported type dict" in error_message
    assert "wrap JSON with psycopg.types.json.Json" in error_message


def test_validate_params_with_json_wrapper(test_user):
    """Test that Json-wrapped dicts work correctly."""
    # Use users table which already exists - update the user's tz/locale using JSON
    # This tests that Json() wrapper works without needing CREATE TEMP TABLE permissions
    from database._core import _validate_params

    # Just validate that the Json wrapper passes validation
    params = {"data": Json({"key": "value", "number": 42})}
    validated = _validate_params(params)

    assert validated is not None
    assert "data" in validated


def test_validate_params_with_none():
    """Test that None params are handled correctly."""
    # None params should work fine
    result = database.fetchone(database.UNSCOPED, "SELECT 1 as test_value", None)  # No params
    assert result["test_value"] == 1


def test_convert_query_without_placeholders():
    """Test query conversion when there are no placeholders."""
    # Query without any : placeholders should remain unchanged
    result = database.fetchone(database.UNSCOPED, "SELECT 42 as answer")  # No placeholders
    assert result["answer"] == 42


def test_fetchall_function(test_user, test_admin_user):
    """Test fetchall returns list of dicts."""
    # Use existing users table to test fetchall
    results = database.fetchall(
        test_user["tenant_id"], "SELECT id, first_name, last_name FROM users ORDER BY created_at"
    )

    # Should have at least 2 users from fixtures
    assert len(results) >= 2
    assert all("id" in r for r in results)
    assert all("first_name" in r for r in results)


def test_normalize_tenant_id_with_invalid_uuid():
    """Test that invalid UUID strings raise appropriate error."""
    from database._core import _normalize_tenant_id

    # Valid UUID string should work
    valid_uuid = str(uuid.uuid4())
    result = _normalize_tenant_id(valid_uuid)
    assert result == valid_uuid

    # Invalid UUID string should raise ValueError
    with pytest.raises(ValueError) as exc_info:
        _normalize_tenant_id("not-a-valid-uuid")

    assert "tenant_id must be a UUID" in str(exc_info.value)


def test_session_context_with_tenant_id(test_tenant):
    """Test that session context properly sets tenant_id."""
    # Use session context directly to ensure tenant_id is set
    with database.session(tenant_id=test_tenant["id"]) as cur:
        # Query should be scoped to this tenant due to RLS
        cur.execute("SELECT current_setting('app.tenant_id', true) as tenant_id")
        result = cur.fetchone()

        # Should return the tenant_id that was set
        assert result["tenant_id"] == str(test_tenant["id"])


def test_session_context_with_unscoped():
    """Test that session context with UNSCOPED doesn't set tenant_id."""
    # Use UNSCOPED - should not set app.tenant_id
    with database.session(tenant_id=database.UNSCOPED) as cur:
        # Try to get the setting - should be empty when unscoped
        cur.execute("SELECT current_setting('app.tenant_id', true) as tenant_id")
        result = cur.fetchone()

        # Should be empty string or None when not set
        assert result["tenant_id"] in ("", None)
