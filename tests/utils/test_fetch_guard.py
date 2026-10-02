"""Tests for utils.fetch_guard: negative cache and per-owner in-flight cap."""

import threading

import pytest
from utils import fetch_guard
from utils.fetch_guard import FetchGuard


class BusyError(Exception):
    pass


def _busy():
    return BusyError("busy")


def test_success_is_returned_and_not_cached():
    guard = FetchGuard()
    calls = []

    def fetch():
        calls.append(1)
        return "ok"

    assert guard.run("c1", "u", fetch, busy=_busy) == "ok"
    assert guard.run("c1", "u", fetch, busy=_busy) == "ok"
    assert len(calls) == 2


def test_failure_is_cached_per_owner_and_key():
    guard = FetchGuard()
    calls = []

    def failing():
        calls.append(1)
        raise ValueError("down")

    with pytest.raises(ValueError, match="down"):
        guard.run("c1", "u", failing, busy=_busy)
    with pytest.raises(ValueError, match="down"):
        guard.run("c1", "u", failing, busy=_busy)
    assert len(calls) == 1

    # Another key, or another owner, is fetched.
    with pytest.raises(ValueError):
        guard.run("c1", "other", failing, busy=_busy)
    with pytest.raises(ValueError):
        guard.run("c2", "u", failing, busy=_busy)
    assert len(calls) == 3


def test_failure_expires(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(fetch_guard.time, "monotonic", lambda: now[0])
    guard = FetchGuard(failure_ttl_seconds=30)

    def failing():
        raise ValueError("down")

    with pytest.raises(ValueError):
        guard.run("c1", "u", failing, busy=_busy)
    now[0] += 31
    assert guard.run("c1", "u", lambda: "back", busy=_busy) == "back"


def test_forget_owner_drops_only_that_owners_failures():
    guard = FetchGuard()

    def failing():
        raise ValueError("down")

    for owner in ("c1", "c2"):
        with pytest.raises(ValueError):
            guard.run(owner, "u", failing, busy=_busy)
    guard.forget_owner("c1")

    assert guard.run("c1", "u", lambda: "ok", busy=_busy) == "ok"
    with pytest.raises(ValueError):
        guard.run("c2", "u", lambda: "ok", busy=_busy)


def test_prunes_expired_failures(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(fetch_guard.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(fetch_guard, "_PRUNE_THRESHOLD", 2)
    guard = FetchGuard(failure_ttl_seconds=10)

    def failing():
        raise ValueError("down")

    for key in ("a", "b"):
        with pytest.raises(ValueError):
            guard.run("c1", key, failing, busy=_busy)
    now[0] = 20
    with pytest.raises(ValueError):
        guard.run("c1", "c", failing, busy=_busy)
    assert list(guard._failures) == [("c1", "c")]


def test_in_flight_cap_fails_fast_then_frees_the_slot():
    guard = FetchGuard(max_in_flight=1)
    started, release = threading.Event(), threading.Event()

    def slow():
        started.set()
        release.wait(5)
        return "slow"

    results = []
    worker = threading.Thread(target=lambda: results.append(guard.run("c1", "u", slow, busy=_busy)))
    worker.start()
    assert started.wait(5)

    with pytest.raises(BusyError):
        guard.run("c1", "u2", lambda: "x", busy=_busy)
    # Another owner is not affected.
    assert guard.run("c2", "u", lambda: "other", busy=_busy) == "other"

    release.set()
    worker.join(5)
    assert results == ["slow"]
    assert guard.run("c1", "u2", lambda: "free", busy=_busy) == "free"


def test_slot_freed_after_failure():
    guard = FetchGuard(max_in_flight=1)

    def failing():
        raise ValueError("down")

    with pytest.raises(ValueError):
        guard.run("c1", "u", failing, busy=_busy)
    assert guard._in_flight == {}
    assert guard.run("c1", "u2", lambda: "ok", busy=_busy) == "ok"
