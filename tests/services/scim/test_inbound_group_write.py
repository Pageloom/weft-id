"""Unit tests for the inbound SCIM group write helpers.

These cover the small payload-shaping helpers in `inbound_group_write`
that don't need a database: display-name extraction, member-array
validation, mutability-style rejection of `members[].value` shapes.

Integration-level coverage (real DB, full create/replace/patch/delete)
lives in `test_inbound_group_write_integration.py`.
"""

from __future__ import annotations

import pytest
from services.scim.inbound_group_write import (
    _MAX_MEMBERS_PER_REQUEST,
    _extract_display_name,
    _resolve_members,
)
from services.scim.inbound_write import ScimWriteError


def test_extract_display_name_returns_stripped_value():
    assert _extract_display_name({"displayName": "  Engineering  "}) == "Engineering"


def test_extract_display_name_returns_none_when_missing():
    assert _extract_display_name({}) is None


def test_extract_display_name_returns_none_when_whitespace_only():
    assert _extract_display_name({"displayName": "   "}) is None


def test_extract_display_name_rejects_non_string():
    with pytest.raises(ScimWriteError) as exc_info:
        _extract_display_name({"displayName": 42})
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidValue"


def test_resolve_members_rejects_non_list():
    with pytest.raises(ScimWriteError) as exc_info:
        _resolve_members("t", "i", "not-a-list")  # type: ignore[arg-type]
    assert exc_info.value.scim_type == "invalidValue"


def test_resolve_members_returns_empty_for_none_or_empty():
    assert _resolve_members("t", "i", None) == []
    assert _resolve_members("t", "i", []) == []


def test_resolve_members_rejects_entry_without_value():
    with pytest.raises(ScimWriteError) as exc_info:
        _resolve_members("t", "i", [{"display": "no value"}])
    assert exc_info.value.scim_type == "invalidValue"


def test_resolve_members_rejects_non_dict_entry():
    with pytest.raises(ScimWriteError) as exc_info:
        _resolve_members("t", "i", ["not-a-dict"])  # type: ignore[list-item]
    assert exc_info.value.scim_type == "invalidValue"


def test_resolve_members_rejects_non_string_value():
    with pytest.raises(ScimWriteError) as exc_info:
        _resolve_members("t", "i", [{"value": 12345}])
    assert exc_info.value.scim_type == "invalidValue"


def test_resolve_members_rejects_oversized_array():
    """A members[] array over the ceiling is rejected before any per-member
    DB resolution, bounding O(N) work on an authenticated endpoint."""
    oversized = [{"value": "x"}] * (_MAX_MEMBERS_PER_REQUEST + 1)
    with pytest.raises(ScimWriteError) as exc_info:
        _resolve_members("t", "i", oversized)
    assert exc_info.value.status_code == 413
