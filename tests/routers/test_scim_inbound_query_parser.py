"""Unit tests for the inbound SCIM query parser helpers.

Lives in `tests/routers/` because the parser is a router-layer
concern (FastAPI consumes its raw query params and passes them in).
But the module is pure Python -- no Request, no DB.
"""

from __future__ import annotations

import pytest
from routers.scim.inbound._query import (
    FilterParseError,
    parse_eq_filter,
    parse_pagination,
)


def test_parse_eq_filter_returns_attr_value():
    assert parse_eq_filter('userName eq "alice@x.test"', allowed_attributes=["userName"]) == (
        "userName",
        "alice@x.test",
    )


def test_parse_eq_filter_handles_whitespace():
    assert parse_eq_filter('   userName   eq   "x"   ', allowed_attributes=["userName"]) == (
        "userName",
        "x",
    )


def test_parse_eq_filter_rejects_other_operators():
    with pytest.raises(FilterParseError) as exc:
        parse_eq_filter('userName co "x"', allowed_attributes=["userName"])
    assert "eq" in exc.value.detail
    assert exc.value.scim_type == "invalidFilter"


def test_parse_eq_filter_rejects_unallowed_attribute():
    with pytest.raises(FilterParseError):
        parse_eq_filter('email eq "x"', allowed_attributes=["userName"])


def test_parse_eq_filter_empty_returns_none():
    assert parse_eq_filter(None, allowed_attributes=["userName"]) is None
    assert parse_eq_filter("", allowed_attributes=["userName"]) is None
    assert parse_eq_filter("   ", allowed_attributes=["userName"]) is None


def test_parse_pagination_defaults():
    assert parse_pagination(None, None) == (1, 100)


def test_parse_pagination_floors_start_index_to_one():
    assert parse_pagination(0, None) == (1, 100)
    assert parse_pagination(-5, None) == (1, 100)


def test_parse_pagination_clamps_count_to_max():
    si, c = parse_pagination(1, 10000, max_count=200)
    assert (si, c) == (1, 200)


def test_parse_pagination_negative_count_to_zero():
    assert parse_pagination(1, -1) == (1, 0)


def test_parse_pagination_preserves_in_range_values():
    assert parse_pagination(5, 50) == (5, 50)
