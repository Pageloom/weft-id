"""Caching for the Directory > Requests nav badge count.

The badge sums pending reactivation requests and users with incomplete
required profiles. Both counts are expensive (the profile-completion count is
a CROSS JOIN over users x attributes), and the badge renders on every
Directory-section page, so the sum is cached per tenant with a short TTL and
invalidated when an admin action changes either count.
"""

from utils import cache

CACHE_TTL_SECONDS = 30
_KEY_PREFIX = "requests_badge_count:"


def get_count(tenant_id: str) -> int | None:
    """Return the cached badge count for a tenant, or None if not cached."""
    value = cache.get(_key(tenant_id))
    return int(value) if value is not None else None


def set_count(tenant_id: str, count: int) -> None:
    """Cache the badge count for a tenant."""
    cache.set(_key(tenant_id), str(count), ttl=CACHE_TTL_SECONDS)


def invalidate(tenant_id: str) -> None:
    """Drop the cached badge count so the next render recomputes it."""
    cache.delete(_key(tenant_id))


def _key(tenant_id: str) -> str:
    return f"{_KEY_PREFIX}{tenant_id}"
