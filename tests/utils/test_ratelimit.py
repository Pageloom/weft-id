"""Tests for rate limiting utilities."""

from unittest.mock import patch

import pytest
from services.exceptions import RateLimitError
from utils.ratelimit import (
    RateLimiter,
)


class TestRateLimiterKeyBuilding:
    """Tests for key building functionality."""

    def test_build_key_simple(self):
        """Should build key with prefix."""
        limiter = RateLimiter()
        key = limiter._build_key("test")
        assert key == "ratelimit:test"

    def test_build_key_with_placeholder(self):
        """Should substitute placeholders."""
        limiter = RateLimiter()
        key = limiter._build_key("login:{email}", email="user@example.com")
        assert key == "ratelimit:login:user@example.com"

    def test_build_key_multiple_placeholders(self):
        """Should substitute multiple placeholders."""
        limiter = RateLimiter()
        key = limiter._build_key("login:{ip}:{email}", ip="192.168.1.1", email="user@example.com")
        assert key == "ratelimit:login:192.168.1.1:user@example.com"


class TestRateLimiterPrevent:
    """Tests for prevent() method."""

    @patch("utils.ratelimit.cache")
    def test_prevent_under_limit(self, mock_cache):
        """Should return count when under limit."""
        mock_cache.incr.return_value = 3
        limiter = RateLimiter()

        count = limiter.prevent("test:{key}", limit=5, timespan=60, key="test")

        assert count == 3
        mock_cache.incr.assert_called_once_with("ratelimit:test:test")

    @patch("utils.ratelimit.cache")
    def test_prevent_at_limit(self, mock_cache):
        """Should return count when at limit (not exceeded)."""
        mock_cache.incr.return_value = 5
        limiter = RateLimiter()

        count = limiter.prevent("test:{key}", limit=5, timespan=60, key="test")

        assert count == 5

    @patch("utils.ratelimit.cache")
    def test_prevent_over_limit_raises(self, mock_cache):
        """Should raise RateLimitError when over limit."""
        mock_cache.incr.return_value = 6
        limiter = RateLimiter()

        with pytest.raises(RateLimitError) as exc_info:
            limiter.prevent("test:{key}", limit=5, timespan=60, key="test")

        assert exc_info.value.limit == 5
        assert exc_info.value.timespan == 60
        assert exc_info.value.retry_after == 60

    @patch("utils.ratelimit.cache")
    def test_prevent_initializes_counter(self, mock_cache):
        """Should initialize counter if it doesn't exist."""
        mock_cache.incr.return_value = None  # Counter doesn't exist
        mock_cache.add.return_value = True  # Successfully created
        limiter = RateLimiter()

        count = limiter.prevent("test", limit=5, timespan=60)

        assert count == 1
        mock_cache.add.assert_called_once()

    @patch("utils.ratelimit.cache")
    def test_prevent_race_condition_handling(self, mock_cache):
        """Should handle race condition when another request creates counter."""
        mock_cache.incr.side_effect = [None, 2]  # First fails, second succeeds
        mock_cache.add.return_value = False  # Another request created the key
        limiter = RateLimiter()

        count = limiter.prevent("test", limit=5, timespan=60)

        assert count == 2
        assert mock_cache.incr.call_count == 2

    @patch("utils.ratelimit.cache")
    def test_prevent_fails_open(self, mock_cache):
        """Should allow request if cache unavailable."""
        mock_cache.incr.return_value = None
        mock_cache.add.return_value = False
        limiter = RateLimiter()

        # Should not raise, should return 0
        count = limiter.prevent("test", limit=5, timespan=60)
        assert count == 0


class TestRateLimiterLog:
    """Tests for log() method."""

    @patch("utils.ratelimit.cache")
    def test_log_under_limit(self, mock_cache):
        """Should return count and False when under limit."""
        mock_cache.incr.return_value = 3
        limiter = RateLimiter()

        count, exceeded = limiter.log("test:{key}", limit=5, timespan=60, key="test")

        assert count == 3
        assert exceeded is False

    @patch("utils.ratelimit.cache")
    def test_log_at_limit(self, mock_cache):
        """Should return count and False when at limit."""
        mock_cache.incr.return_value = 5
        limiter = RateLimiter()

        count, exceeded = limiter.log("test", limit=5, timespan=60)

        assert count == 5
        assert exceeded is False

    @patch("utils.ratelimit.cache")
    def test_log_over_limit(self, mock_cache):
        """Should return count and True when over limit."""
        mock_cache.incr.return_value = 6
        limiter = RateLimiter()

        count, exceeded = limiter.log("test", limit=5, timespan=60)

        assert count == 6
        assert exceeded is True

    @patch("utils.ratelimit.cache")
    def test_log_fails_open(self, mock_cache):
        """Should return 0 and False if cache unavailable."""
        mock_cache.incr.return_value = None
        mock_cache.add.return_value = False
        limiter = RateLimiter()

        count, exceeded = limiter.log("test", limit=5, timespan=60)

        assert count == 0
        assert exceeded is False


class TestRateLimiterCheck:
    """Tests for check() method."""

    @patch("utils.ratelimit.cache")
    def test_check_under_limit(self, mock_cache):
        """Should return count and False when under limit."""
        mock_cache.get.return_value = b"3"
        limiter = RateLimiter()

        count, exceeded = limiter.check("test:{key}", limit=5, key="test")

        assert count == 3
        assert exceeded is False

    @patch("utils.ratelimit.cache")
    def test_check_over_limit(self, mock_cache):
        """Should return count and True when over limit."""
        mock_cache.get.return_value = b"10"
        limiter = RateLimiter()

        count, exceeded = limiter.check("test", limit=5)

        assert count == 10
        assert exceeded is True

    @patch("utils.ratelimit.cache")
    def test_check_no_counter(self, mock_cache):
        """Should return 0 and False when counter doesn't exist."""
        mock_cache.get.return_value = None
        limiter = RateLimiter()

        count, exceeded = limiter.check("test", limit=5)

        assert count == 0
        assert exceeded is False

    @patch("utils.ratelimit.cache")
    def test_check_invalid_value(self, mock_cache):
        """Should return 0 and False when counter value is invalid."""
        mock_cache.get.return_value = b"invalid"
        limiter = RateLimiter()

        count, exceeded = limiter.check("test", limit=5)

        assert count == 0
        assert exceeded is False


class TestRateLimiterReset:
    """Tests for reset() method."""

    @patch("utils.ratelimit.cache")
    def test_reset_success(self, mock_cache):
        """Should return True on successful reset."""
        mock_cache.delete.return_value = True
        limiter = RateLimiter()

        result = limiter.reset("test:{key}", key="test")

        assert result is True
        mock_cache.delete.assert_called_once_with("ratelimit:test:test")

    @patch("utils.ratelimit.cache")
    def test_reset_failure(self, mock_cache):
        """Should return False on failed reset."""
        mock_cache.delete.return_value = False
        limiter = RateLimiter()

        result = limiter.reset("test")

        assert result is False


class TestRateLimitErrorException:
    """Tests for RateLimitError exception attributes."""

    def test_exception_attributes(self):
        """Should have correct attributes."""
        exc = RateLimitError(
            message="Too many requests",
            limit=10,
            timespan=60,
            retry_after=60,
        )

        assert exc.message == "Too many requests"
        assert exc.code == "rate_limit_exceeded"
        assert exc.limit == 10
        assert exc.timespan == 60
        assert exc.retry_after == 60

    def test_exception_str(self):
        """Should use message for string representation."""
        exc = RateLimitError(message="Custom message")
        assert str(exc) == "Custom message"


class TestRateLimiterCounting:
    """End-to-end against the in-memory backend: no mocks, real counting.

    These guard the property the suite relies on: a rate limit that is
    configured actually trips under test, instead of failing open because
    Memcached is unreachable.
    """

    def test_prevent_trips_past_limit(self):
        limiter = RateLimiter()
        for _ in range(5):
            limiter.prevent("count:{k}", limit=5, timespan=60, k="a")
        with pytest.raises(RateLimitError):
            limiter.prevent("count:{k}", limit=5, timespan=60, k="a")

    def test_keys_are_independent(self):
        limiter = RateLimiter()
        for _ in range(5):
            limiter.prevent("count:{k}", limit=5, timespan=60, k="a")
        # A different key has its own bucket.
        assert limiter.prevent("count:{k}", limit=5, timespan=60, k="b") == 1

    def test_window_expiry_resets_counter(self, memory_cache):
        base = memory_cache.clock()
        memory_cache.clock = lambda: base
        limiter = RateLimiter()
        for _ in range(5):
            limiter.prevent("count:{k}", limit=5, timespan=60, k="a")
        with pytest.raises(RateLimitError):
            limiter.prevent("count:{k}", limit=5, timespan=60, k="a")

        memory_cache.clock = lambda: base + 60
        assert limiter.prevent("count:{k}", limit=5, timespan=60, k="a") == 1

    def test_check_and_reset(self):
        limiter = RateLimiter()
        limiter.prevent("count:{k}", limit=5, timespan=60, k="a")
        limiter.prevent("count:{k}", limit=5, timespan=60, k="a")
        assert limiter.check("count:{k}", limit=5, k="a") == (2, False)
        assert limiter.reset("count:{k}", k="a") is True
        assert limiter.check("count:{k}", limit=5, k="a") == (0, False)

    def test_log_reports_exceeded(self):
        limiter = RateLimiter()
        for _ in range(3):
            limiter.log("soft:{k}", limit=3, timespan=60, k="a")
        assert limiter.log("soft:{k}", limit=3, timespan=60, k="a") == (4, True)

    def test_state_does_not_leak_between_tests(self):
        """Each test gets a fresh backend, so this bucket starts at zero."""
        limiter = RateLimiter()
        assert limiter.check("count:{k}", limit=5, k="a") == (0, False)
        assert limiter.prevent("count:{k}", limit=5, timespan=60, k="a") == 1
