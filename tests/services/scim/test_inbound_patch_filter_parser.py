"""Unit tests for `_normalise_patch_path_with_filter` (iteration 4).

The user-PATCH path uses `_normalise_patch_path` which discards element
filters. The group-PATCH path needs the filter value to know which
single member to remove. The shared helper
`_normalise_patch_path_with_filter` returns both pieces so each PATCH
verb can use what it needs.
"""

from __future__ import annotations

from services.scim.inbound_write import (
    _normalise_patch_path,
    _normalise_patch_path_with_filter,
    _parse_eq_filter,
)


def test_simple_path_returns_lowercased_with_no_filter():
    path, filter_kv = _normalise_patch_path_with_filter("displayName")
    assert path == "displayname"
    assert filter_kv is None


def test_dotted_path_lowercased():
    path, filter_kv = _normalise_patch_path_with_filter("name.givenName")
    assert path == "name.givenname"
    assert filter_kv is None


def test_element_filter_double_quoted_returns_filter():
    path, filter_kv = _normalise_patch_path_with_filter('members[value eq "abc-123"]')
    assert path == "members"
    assert filter_kv == ("value", "abc-123")


def test_element_filter_single_quoted_returns_filter():
    path, filter_kv = _normalise_patch_path_with_filter("members[value eq 'xyz']")
    assert path == "members"
    assert filter_kv == ("value", "xyz")


def test_emails_with_type_filter_returns_filter():
    """User PATCH path discards this filter (whole-collection); the
    helper still returns it for callers that need it (group remove)."""
    path, filter_kv = _normalise_patch_path_with_filter('emails[type eq "work"]')
    assert path == "emails"
    assert filter_kv == ("type", "work")


def test_normalise_patch_path_unchanged_for_users():
    """The legacy `_normalise_patch_path` continues to strip the filter
    cleanly -- user-PATCH tests rely on this."""
    assert _normalise_patch_path('members[value eq "uuid-abc"]') == "members"
    assert _normalise_patch_path('emails[type eq "work"]') == "emails"
    assert _normalise_patch_path("displayName") == "displayname"
    assert _normalise_patch_path(None) is None


def test_enterprise_urn_prefix_normalised():
    path, filter_kv = _normalise_patch_path_with_filter(
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"
    )
    assert path == "enterprise.department"
    assert filter_kv is None


def test_malformed_filter_no_close_bracket_falls_back():
    """Defensive: a malformed filter should not crash; we return the
    prefix and no filter."""
    path, filter_kv = _normalise_patch_path_with_filter('members[value eq "abc"')
    assert path == "members"
    assert filter_kv is None


def test_filter_that_is_not_eq_returns_none_filter():
    """`co` (contains) is not supported -- helper returns None for the
    filter so the caller can reject the op."""
    path, filter_kv = _normalise_patch_path_with_filter('members[value co "abc"]')
    assert path == "members"
    assert filter_kv is None


def test_parse_eq_filter_returns_none_for_too_few_parts():
    """A filter body with fewer than 3 whitespace-separated tokens is malformed."""
    assert _parse_eq_filter("value eq") is None
    assert _parse_eq_filter("value") is None
    assert _parse_eq_filter("") is None


def test_parse_eq_filter_value_with_embedded_spaces():
    """The third part may itself contain spaces inside quotes; split with
    maxsplit=2 preserves them."""
    result = _parse_eq_filter('value eq "abc def ghi"')
    assert result == ("value", "abc def ghi")


def test_parse_eq_filter_value_without_quotes_preserved():
    """Bare values without surrounding quotes are returned as-is."""
    result = _parse_eq_filter("value eq plain")
    assert result == ("value", "plain")


def test_parse_eq_filter_returns_none_when_operator_not_eq():
    assert _parse_eq_filter('value ne "x"') is None
    assert _parse_eq_filter('value sw "abc"') is None


def test_parse_eq_filter_mismatched_quotes_preserved_intact():
    """A value with single quote on one side and double quote on the other
    is not stripped (defensive: don't fabricate a malformed value)."""
    result = _parse_eq_filter("value eq \"abc'")
    # Mismatched quotes: the strip-quote heuristic only triggers when both
    # ends are the same character. The value is returned as-is.
    assert result is not None
    attr, value = result
    assert attr == "value"
    # No strip because first and last chars differ.
    assert value == "\"abc'"


def test_normalise_patch_path_with_subattribute_after_bracket_drops_it():
    """`emails[type eq "work"].value` reduces to `emails` -- subattribute
    after the closing bracket is intentionally dropped (whole-collection
    semantics)."""
    path, filter_kv = _normalise_patch_path_with_filter('emails[type eq "work"].value')
    assert path == "emails"
    assert filter_kv == ("type", "work")


def test_normalise_patch_path_with_filter_handles_none():
    """None path passes through cleanly."""
    path, filter_kv = _normalise_patch_path_with_filter(None)
    assert path is None
    assert filter_kv is None


def test_normalise_patch_path_with_filter_handles_whitespace_path():
    """A path that is just whitespace strips to empty and returns lowercased empty."""
    path, filter_kv = _normalise_patch_path_with_filter("  ")
    # The path strips to "" but no bracket / no URN -- returns ("", None).
    assert filter_kv is None
    assert path == ""
