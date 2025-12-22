"""Memcached cache utilities for activity tracking and other caching needs."""

import logging
from typing import Any

import settings

logger = logging.getLogger(__name__)

_client = None


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
