"""Tests for database module."""

import database
import pytest


def test_unscoped_constant():
    """Test UNSCOPED constant exists and has correct representation."""
    assert database.UNSCOPED is not None
    assert repr(database.UNSCOPED) == "UNSCOPED"


def test_normalize_tenant_id_with_unscoped():
    """Test _normalize_tenant_id with UNSCOPED returns None."""
    result = database._normalize_tenant_id(database.UNSCOPED)
    assert result is None


def test_normalize_tenant_id_with_invalid_uuid():
    """Test _normalize_tenant_id with invalid UUID raises ValueError."""
    with pytest.raises(ValueError, match="UUID"):
        database._normalize_tenant_id("not-a-uuid")


def test_validate_params_with_none():
    """Test _validate_params with None returns None."""
    result = database._validate_params(None)
    assert result is None


def test_validate_params_with_valid_dict():
    """Test _validate_params with valid parameters."""
    params = {"key": "value", "number": 42}
    result = database._validate_params(params)
    assert result == params


def test_validate_params_with_invalid_dict_value():
    """Test _validate_params with invalid dict value raises RuntimeError."""
    params = {"key": {"nested": "dict"}}
    with pytest.raises(RuntimeError, match="unsupported type"):
        database._validate_params(params)
