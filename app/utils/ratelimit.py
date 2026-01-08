"""Rate limiting utilities using Memcached.

This module provides simple rate limiting with two modes:
- `log()`: Soft limit - increments counter and logs when exceeded
- `prevent()`: Hard limit - raises RateLimitExceeded when exceeded

Both functions increment the counter on every call (not just checking).
The caller is responsible for using different key patterns for different purposes.

Usage:
    from utils.ratelimit import ratelimit, MINUTE, HOUR

    # Soft limit - logs warning when exceeded
    count, exceeded = ratelimit.log(
        'login_attempts:ip:{ip}:email:{email}',
        limit=5,
        timespan=MINUTE*5,
        ip='192.168.1.1',
        email='user@example.com'
    )

    # Hard limit - raises exception when exceeded
    ratelimit.prevent(
        'login_block:ip:{ip}:email:{email}',
        limit=20,
        timespan=MINUTE*15,
        ip='192.168.1.1',
        email='user@example.com'
    )
"""

import logging

from services.exceptions import RateLimitError
from utils import cache

logger = logging.getLogger(__name__)

# Time constants
SECOND = 1
MINUTE = 60
HOUR = 3600

# Key prefix to avoid collision with other cache uses
KEY_PREFIX = "ratelimit:"


class RateLimiter:
    """Rate limiter using Memcached atomic counters."""

    def _build_key(self, pattern: str, **kwargs) -> str:
        """Build cache key from pattern and keyword arguments.

        Args:
            pattern: Key pattern with placeholders like 'login:{ip}:{email}'
            **kwargs: Values to substitute into pattern

        Returns:
            Full cache key with prefix
        """
        key = pattern.format(**kwargs)
        return f"{KEY_PREFIX}{key}"

    def _increment(self, key: str, timespan: int) -> int | None:
        """Atomically increment counter, initializing if needed.

        Returns the new count, or None if cache unavailable.
        """
        # Try to increment existing counter
        count = cache.incr(key)
        if count is not None:
            return count

        # Counter doesn't exist - try to create it atomically
        # add() only succeeds if key doesn't exist (prevents race condition)
        if cache.add(key, b"1", ttl=timespan):
            return 1

        # Another request created the key between our incr and add
        # Try incr again
        count = cache.incr(key)
        return count

    def prevent(
        self,
        pattern: str,
        limit: int,
        timespan: int,
        **kwargs,
    ) -> int:
        """Hard rate limit - increment counter and raise if limit exceeded.

        Args:
            pattern: Key pattern with placeholders (e.g., 'login:{ip}:{email}')
            limit: Maximum number of requests allowed in timespan
            timespan: Window size in seconds
            **kwargs: Values to substitute into pattern

        Returns:
            Current count after increment

        Raises:
            RateLimitExceeded: If limit is exceeded
        """
        key = self._build_key(pattern, **kwargs)
        count = self._increment(key, timespan)

        # Fail open if cache unavailable
        if count is None:
            logger.warning("Rate limit check failed (cache unavailable): %s", key)
            return 0

        if count > limit:
            logger.warning(
                "Rate limit exceeded: %s (count=%d, limit=%d)",
                key,
                count,
                limit,
            )
            raise RateLimitError(
                message="Too many requests. Please try again later.",
                limit=limit,
                timespan=timespan,
                retry_after=timespan,
            )

        return count

    def log(
        self,
        pattern: str,
        limit: int,
        timespan: int,
        **kwargs,
    ) -> tuple[int, bool]:
        """Soft rate limit - increment counter and log if limit exceeded.

        Args:
            pattern: Key pattern with placeholders (e.g., 'login_attempts:{ip}:{email}')
            limit: Maximum number of requests before logging warning
            timespan: Window size in seconds
            **kwargs: Values to substitute into pattern

        Returns:
            Tuple of (current_count, exceeded) where exceeded is True if over limit
        """
        key = self._build_key(pattern, **kwargs)
        count = self._increment(key, timespan)

        # Fail open if cache unavailable
        if count is None:
            logger.warning("Rate limit check failed (cache unavailable): %s", key)
            return (0, False)

        exceeded = count > limit
        if exceeded:
            logger.warning(
                "Rate limit soft exceeded: %s (count=%d, limit=%d)",
                key,
                count,
                limit,
            )

        return (count, exceeded)

    def check(
        self,
        pattern: str,
        limit: int,
        **kwargs,
    ) -> tuple[int, bool]:
        """Check current count without incrementing.

        Args:
            pattern: Key pattern with placeholders
            limit: Limit to check against
            **kwargs: Values to substitute into pattern

        Returns:
            Tuple of (current_count, exceeded) where exceeded is True if over limit
        """
        key = self._build_key(pattern, **kwargs)
        value = cache.get(key)

        if value is None:
            return (0, False)

        try:
            count = int(value)
        except (ValueError, TypeError):
            return (0, False)

        return (count, count > limit)

    def reset(self, pattern: str, **kwargs) -> bool:
        """Reset a rate limit counter.

        Args:
            pattern: Key pattern with placeholders
            **kwargs: Values to substitute into pattern

        Returns:
            True if deleted successfully, False otherwise
        """
        key = self._build_key(pattern, **kwargs)
        return cache.delete(key)


# Module singleton
ratelimit = RateLimiter()
