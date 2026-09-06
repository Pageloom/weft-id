"""Tests for utils.requests_badge caching.

The ``memory_cache`` autouse fixture installs a fresh in-memory cache per test,
so these exercise the real get/set/invalidate path against the module-level
``utils.cache`` functions.
"""

from utils import requests_badge


def test_get_count_returns_none_when_not_cached():
    assert requests_badge.get_count("tenant-1") is None


def test_set_then_get_round_trip():
    requests_badge.set_count("tenant-1", 7)
    assert requests_badge.get_count("tenant-1") == 7


def test_invalidate_drops_cached_value():
    requests_badge.set_count("tenant-1", 7)
    requests_badge.invalidate("tenant-1")
    assert requests_badge.get_count("tenant-1") is None


def test_counts_are_scoped_per_tenant():
    requests_badge.set_count("tenant-1", 7)
    assert requests_badge.get_count("tenant-2") is None
