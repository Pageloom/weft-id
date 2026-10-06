"""Server-side upstream sign-in state (``services.oidc_upstream.login_state``)."""

import hashlib
import json

import pytest
from services.oidc_upstream import login_state as store
from services.oidc_upstream.login_state import LoginState


def _state(**overrides) -> LoginState:
    values = {
        "tenant_id": "t-1",
        "connection_id": "c-1",
        "nonce": "n-1",
        "code_verifier": "v-1",
        "entry": "routed",
    }
    values.update(overrides)
    return LoginState(**values)


def _key(state: str) -> str:
    return "oidc_login_state:" + hashlib.sha256(state.encode()).hexdigest()


class TestSaveAndLoad:
    def test_round_trip(self):
        assert store.save_login_state("s-1", _state(entry="login_button"))
        assert store.load_login_state("s-1") == _state(entry="login_button")

    def test_key_is_a_hash_of_state(self, memory_cache):
        store.save_login_state("raw-state-value", _state())
        assert memory_cache.get(_key("raw-state-value")) is not None
        assert not any("raw-state-value" in key for key in memory_cache._store)

    def test_save_does_not_overwrite(self):
        assert store.save_login_state("s-1", _state())
        assert not store.save_login_state("s-1", _state(nonce="other"))
        assert store.load_login_state("s-1").nonce == "n-1"

    def test_save_fails_without_store(self, monkeypatch):
        from utils import cache

        monkeypatch.setattr(cache, "get_client", lambda: None)
        assert store.save_login_state("s-1", _state()) is False

    def test_unknown_or_empty_state(self):
        assert store.load_login_state("nope") is None
        assert store.load_login_state("") is None

    def test_expires(self, memory_cache):
        now = [1000.0]
        memory_cache.clock = lambda: now[0]
        store.save_login_state("s-1", _state())
        now[0] += store.LOGIN_STATE_TTL - 1
        assert store.load_login_state("s-1") is not None
        now[0] += 2
        assert store.load_login_state("s-1") is None

    @pytest.mark.parametrize(
        "raw",
        [
            b"not json",
            b"[]",
            json.dumps({"tenant_id": "t-1"}).encode(),
            json.dumps(
                {
                    "tenant_id": "t-1",
                    "connection_id": "c-1",
                    "nonce": 5,
                    "code_verifier": "v",
                    "entry": "routed",
                }
            ).encode(),
            json.dumps(
                {
                    "tenant_id": "t-1",
                    "connection_id": "c-1",
                    "nonce": "n",
                    "code_verifier": "v",
                    "entry": "routed",
                    "callback_fields": {"code": 5},
                }
            ).encode(),
        ],
    )
    def test_malformed_entry(self, memory_cache, raw):
        memory_cache.set(_key("s-1"), raw)
        assert store.load_login_state("s-1") is None


class TestTake:
    def test_single_use(self):
        store.save_login_state("s-1", _state())
        assert store.take_login_state("s-1") == _state()
        assert store.take_login_state("s-1") is None

    def test_unknown(self):
        assert store.take_login_state("nope") is None


class TestAttachCallbackFields:
    def test_kept_fields_only(self):
        store.save_login_state("s-1", _state())
        assert store.attach_callback_fields(
            "s-1",
            store.load_login_state("s-1"),
            {"code": "c", "user": "{}", "error": "", "id_token": "x", "state": "s-1"},
        )
        assert store.load_login_state("s-1").callback_fields == {"code": "c", "user": "{}"}

    def test_only_once(self):
        store.save_login_state("s-1", _state())
        assert store.attach_callback_fields("s-1", store.load_login_state("s-1"), {"code": "a"})
        assert not store.attach_callback_fields("s-1", store.load_login_state("s-1"), {"code": "b"})
        assert store.load_login_state("s-1").callback_fields == {"code": "a"}

    def test_concurrent_posts_attach_once(self):
        """Two posts that both loaded the entry before either wrote: one wins."""
        store.save_login_state("s-1", _state())
        first = store.load_login_state("s-1")
        second = store.load_login_state("s-1")
        assert store.attach_callback_fields("s-1", first, {"code": "a"})
        assert not store.attach_callback_fields("s-1", second, {"code": "b"})
        assert store.load_login_state("s-1").callback_fields == {"code": "a"}

    def test_keeps_the_rest(self):
        store.save_login_state("s-1", _state(entry="login_button"))
        store.attach_callback_fields("s-1", store.load_login_state("s-1"), {"error": "denied"})
        loaded = store.take_login_state("s-1")
        assert loaded.entry == "login_button"
        assert loaded.nonce == "n-1"
        assert loaded.callback_fields == {"error": "denied"}
