"""Bounds on outbound fetches a client can make WeftID perform.

A registered client controls some URLs WeftID fetches on its behalf (its
``request_uri`` documents, ``jwks_uri``, ``sector_identifier_uri``). Every fetch
is already bounded in time and size; this adds two limits per client, so a
slow or failing URL cannot tie up many server threads:

- **Negative cache**: a failed fetch is remembered for a short while, and the
  same fetch fails at once with the same error instead of being retried.
- **In-flight cap**: at most ``max_in_flight`` fetches run at once for one
  owner (a client); more fail at once.

State is per process, like the JWKS cache.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Hashable
from typing import TypeVar

T = TypeVar("T")

DEFAULT_FAILURE_TTL_SECONDS = 30.0
# Past this many cached failures, expired ones are pruned on the next insert.
_PRUNE_THRESHOLD = 1024


class FetchGuard:
    def __init__(
        self,
        *,
        max_in_flight: int = 1,
        failure_ttl_seconds: float = DEFAULT_FAILURE_TTL_SECONDS,
    ) -> None:
        self._max_in_flight = max_in_flight
        self._failure_ttl = failure_ttl_seconds
        self._lock = threading.Lock()
        self._in_flight: dict[Hashable, int] = {}
        self._failures: dict[tuple[Hashable, Hashable], tuple[float, BaseException]] = {}

    def run(
        self,
        owner: Hashable,
        key: Hashable,
        fetch: Callable[[], T],
        *,
        busy: Callable[[], BaseException],
    ) -> T:
        """Run ``fetch`` for ``owner`` (whose limit applies) and ``key`` (what
        is fetched, e.g. the URL; failures are cached per owner and key).

        Raises the cached error of a recent failure of ``key``, ``busy()`` when
        ``owner`` already has ``max_in_flight`` fetches running, or whatever
        ``fetch`` raises (which is then cached).
        """
        now = time.monotonic()
        entry = (owner, key)
        with self._lock:
            failure = self._failures.get(entry)
            if failure is not None:
                if now - failure[0] < self._failure_ttl:
                    # Re-raised as is, as concurrent.futures does.
                    raise failure[1]
                del self._failures[entry]
            if self._in_flight.get(owner, 0) >= self._max_in_flight:
                raise busy()
            self._in_flight[owner] = self._in_flight.get(owner, 0) + 1

        try:
            result = fetch()
        except Exception as exc:
            with self._lock:
                failed_at = time.monotonic()
                if len(self._failures) >= _PRUNE_THRESHOLD:
                    self._failures = {
                        k: v
                        for k, v in self._failures.items()
                        if failed_at - v[0] < self._failure_ttl
                    }
                self._failures[entry] = (failed_at, exc)
            raise
        finally:
            with self._lock:
                remaining = self._in_flight[owner] - 1
                if remaining:
                    self._in_flight[owner] = remaining
                else:
                    del self._in_flight[owner]
        return result

    def forget_owner(self, owner: Hashable) -> None:
        """Drop an owner's cached failures (e.g. it changed its metadata)."""
        with self._lock:
            self._failures = {k: v for k, v in self._failures.items() if k[0] != owner}

    def clear(self) -> None:
        """Drop all state (tests)."""
        with self._lock:
            self._in_flight.clear()
            self._failures.clear()
