"""Memcached cache utilities for activity tracking and other caching needs.

The module-level functions talk to whatever client :func:`get_client` returns.
In production that is a pymemcache client; :class:`MemoryCache` is a drop-in
in-process stand-in with the same call surface (``get``/``set``/``delete``/
``incr``/``add`` with ``expire``) so rate limits, replay guards, and activity
dedup can be exercised deterministically without a Memcached server. The
test suite installs a fresh ``MemoryCache`` per test.
"""

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import settings

logger = logging.getLogger(__name__)

_client = None


class MemoryCache:
    """In-process cache with pymemcache-compatible semantics.

    - ``incr`` on a missing key returns ``None`` (Memcached does not
      auto-create counters); on a non-numeric value it raises, which the
      module-level wrapper turns into ``None``.
    - ``add`` succeeds only when the key is absent (or expired).
    - ``expire=0`` means no expiry. Expiry is evaluated lazily against
      ``clock``, which tests may replace to advance time.

    All operations hold one lock, so increments are atomic across threads
    (the TestClient runs the app in a worker thread).
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self._lock = threading.Lock()
        self._store: dict[str, tuple[bytes, float | None]] = {}

    @staticmethod
    def _to_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        return str(value).encode()

    def _live(self, key: str) -> bytes | None:
        """Return the value if present and unexpired, purging it otherwise."""
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and self.clock() >= expires_at:
            del self._store[key]
            return None
        return value

    def _expiry(self, expire: int) -> float | None:
        return None if expire == 0 else self.clock() + expire

    def get(self, key: str) -> bytes | None:
        with self._lock:
            return self._live(key)

    def set(self, key: str, value: Any, expire: int = 0) -> bool:
        with self._lock:
            self._store[key] = (self._to_bytes(value), self._expiry(expire))
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def add(self, key: str, value: Any, expire: int = 0) -> bool:
        with self._lock:
            if self._live(key) is not None:
                return False
            self._store[key] = (self._to_bytes(value), self._expiry(expire))
            return True

    def incr(self, key: str, value: int = 1) -> int | None:
        with self._lock:
            current = self._live(key)
            if current is None:
                return None
            new_value = int(current) + value
            _, expires_at = self._store[key]
            self._store[key] = (str(new_value).encode(), expires_at)
            return new_value

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


def get_client():
    """Get or create Memcached client (lazy initialization).

    Returns the client instance or None if connection fails.
    """
    global _client
    if _client is None:
        try:
            from pymemcache.client import base

            _client = base.Client(
                (settings.MEMCACHED_HOST, settings.MEMCACHED_PORT),
                connect_timeout=1,
                timeout=1,
            )
        except Exception as e:
            logger.warning("Failed to connect to Memcached: %s", e)
            return None
    return _client


def get(key: str) -> bytes | None:
    """Get a value from cache.

    Returns the cached value as bytes, or None if not found or on error.
    """
    client = get_client()
    if client is None:
        return None
    try:
        result = client.get(key)
        return result if result is None else bytes(result)
    except Exception as e:
        logger.warning("Memcached get failed for key %s: %s", key, e)
        return None


def set(key: str, value: Any, ttl: int = 0) -> bool:
    """Set a value in cache.

    Args:
        key: Cache key
        value: Value to store (will be converted to bytes if not already)
        ttl: Time-to-live in seconds (0 = no expiration)

    Returns True on success, False on error.
    """
    client = get_client()
    if client is None:
        return False
    try:
        client.set(key, value, expire=ttl)
        return True
    except Exception as e:
        logger.warning("Memcached set failed for key %s: %s", key, e)
        return False


def delete(key: str) -> bool:
    """Delete a key from cache.

    Returns True on success, False on error.
    """
    client = get_client()
    if client is None:
        return False
    try:
        client.delete(key)
        return True
    except Exception as e:
        logger.warning("Memcached delete failed for key %s: %s", key, e)
        return False


def incr(key: str, value: int = 1) -> int | None:
    """Atomically increment a counter in cache.

    Args:
        key: Cache key
        value: Amount to increment by (default 1)

    Returns the new value after increment, or None on error.
    Note: If key doesn't exist, Memcached returns None (does not auto-create).
    """
    client = get_client()
    if client is None:
        return None
    try:
        result: int | None = client.incr(key, value)
        return result
    except Exception as e:
        logger.warning("Memcached incr failed for key %s: %s", key, e)
        return None


def add(key: str, value: Any, ttl: int = 0) -> bool:
    """Add a key only if it doesn't already exist.

    Args:
        key: Cache key
        value: Value to store
        ttl: Time-to-live in seconds (0 = no expiration)

    Returns True if key was added (didn't exist), False if key exists or on error.
    """
    client = get_client()
    if client is None:
        return False
    try:
        result: bool = client.add(key, value, expire=ttl)
        return result
    except Exception as e:
        logger.warning("Memcached add failed for key %s: %s", key, e)
        return False
