"""Unit tests for the conformance runner's operator hooks (dev/oidc_conformance_hooks.py).

The hooks patch the suite's ``Conformance`` client in-process; these tests
use a stand-in class with the same async methods.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def hooks():
    src = PROJECT_ROOT / "dev" / "oidc_conformance_hooks.py"
    spec = importlib.util.spec_from_file_location("oidc_conformance_hooks_under_test", src)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["oidc_conformance_hooks_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _fake_conformance(test_name: str, events: list[str]) -> type:
    class FakeConformance:
        async def get_module_info(self, module_id):
            return {"id": module_id, "testName": test_name}

        async def start_test(self, module_id):
            events.append(f"start {module_id}")
            return {"started": module_id}

        async def wait_for_state(self, module_id, required_states, timeout=240):
            events.append(f"wait {module_id} {','.join(required_states)}")
            return required_states[-1]

    return FakeConformance


class TestInstallHooks:
    def test_rotation_module_rotates_before_it_starts(self, hooks):
        events: list[str] = []
        cls = _fake_conformance("oidcc-server-rotate-keys", events)
        hooks.install_hooks(cls, lambda: events.append("rotate"))

        result = asyncio.run(cls().start_test("m1"))

        assert events == ["rotate", "start m1"]
        assert result == {"started": "m1"}

    def test_other_modules_start_without_rotating(self, hooks):
        events: list[str] = []
        cls = _fake_conformance("oidcc-server", events)
        hooks.install_hooks(cls, lambda: events.append("rotate"))

        asyncio.run(cls().start_test("m2"))

        assert events == ["start m2"]

    def test_rotation_failure_stops_the_start(self, hooks):
        events: list[str] = []
        cls = _fake_conformance("oidcc-server-rotate-keys", events)

        def rotate():
            raise hooks.HookError("no docker")

        hooks.install_hooks(cls, rotate)
        with pytest.raises(hooks.HookError):
            asyncio.run(cls().start_test("m3"))
        assert events == []


class _Result:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestRotateSigningKey:
    def test_runs_the_testbed_rotation_in_the_app_container(self, hooks, capsys):
        seen: list[list[str]] = []

        def run(cmd, **kwargs):
            seen.append(cmd)
            return _Result(0, json.dumps({"kid": "new", "previous_kid": "old"}))

        assert hooks.rotate_signing_key(run=run) == {"kid": "new", "previous_kid": "old"}
        (cmd,) = seen
        assert cmd[-4:] == ["app", "python", hooks.TESTBED_SCRIPT, "--rotate-signing-key-flag"]
        assert "old -> new" in capsys.readouterr().out

    def test_failure_is_reported(self, hooks):
        with pytest.raises(hooks.HookError, match="rc=1.*boom"):
            hooks.rotate_signing_key(run=lambda cmd, **kw: _Result(1, stderr="boom"))


class TestRpDriver:
    """RP modules: the patched wait_for_state drives WeftID before waiting."""

    def _install(self, hooks, test_name, events):
        cls = _fake_conformance(test_name, events)
        hooks.install_hooks(cls, lambda: None, lambda module: events.append(f"drive {module}"))
        return cls

    def test_rp_module_is_driven_once_before_waiting_for_finish(self, hooks):
        events: list[str] = []
        cls = self._install(hooks, "oidcc-client-test-invalid-iss", events)
        client = cls()

        asyncio.run(client.wait_for_state("m1", ["CONFIGURED", "WAITING", "FINISHED"]))
        asyncio.run(client.wait_for_state("m1", ["FINISHED"]))
        asyncio.run(client.wait_for_state("m1", ["FINISHED"]))

        assert events == [
            "wait m1 CONFIGURED,WAITING,FINISHED",
            "drive oidcc-client-test-invalid-iss",
            "wait m1 FINISHED",
            "wait m1 FINISHED",
        ]

    def test_op_module_is_not_driven(self, hooks):
        events: list[str] = []
        cls = self._install(hooks, "oidcc-server", events)
        asyncio.run(cls().wait_for_state("m2", ["FINISHED"]))
        assert events == ["wait m2 FINISHED"]

    def test_no_driver_leaves_rp_modules_alone(self, hooks):
        events: list[str] = []
        cls = _fake_conformance("oidcc-client-test", events)
        hooks.install_hooks(cls, lambda: None)
        asyncio.run(cls().wait_for_state("m3", ["FINISHED"]))
        assert events == ["wait m3 FINISHED"]


class TestRunRpModule:
    def test_sign_in_module_expires_discovery_then_signs_in(self, hooks, capsys):
        calls: list[str] = []
        hooks.run_rp_module(
            "oidcc-client-test-nonce-invalid",
            "https://t.example/auth/oidc/c/login",
            expire=lambda: calls.append("expire"),
            test_connection=lambda: calls.append("test") or {},
            sign_in=lambda url: (
                calls.append(f"sign-in {url}")
                or [url, "https://t.example/login?error=auth_failed", "HTTP 200"]
            ),
        )
        assert calls == ["expire", "sign-in https://t.example/auth/oidc/c/login"]
        out = capsys.readouterr().out
        assert "t.example/login?error=auth_failed" in out

    @pytest.mark.parametrize(
        "module",
        sorted(
            [
                "oidcc-client-test-discovery-openid-config",
                "oidcc-client-test-discovery-jwks-uri-keys",
            ]
        ),
    )
    def test_discovery_only_modules_use_test_connection(self, hooks, module):
        calls: list[str] = []
        hooks.run_rp_module(
            module,
            "https://t.example/login",
            expire=lambda: calls.append("expire"),
            test_connection=lambda: calls.append("test") or {"result": "success"},
            sign_in=lambda url: calls.append("sign-in") or [],
        )
        assert calls == ["test"]

    @pytest.mark.parametrize(
        "module",
        [
            "oidcc-client-test-rp-init-logout",
            "oidcc-client-test-rp-init-logout-no-state",
            "oidcc-client-test-rp-backchannel-rpinitlogout",
            "oidcc-client-test-rp-backchannel-rpinitlogout-wrong-iss",
        ],
    )
    def test_logout_modules_sign_in_and_out(self, hooks, module, capsys):
        calls: list[str] = []
        hooks.run_rp_module(
            module,
            "https://t.example/login",
            expire=lambda: calls.append("expire"),
            test_connection=lambda: calls.append("test") or {},
            sign_in=lambda url: calls.append("sign-in") or [],
            sign_in_and_out=lambda url: calls.append("sign-in-and-out") or [url, "logout"],
        )
        assert calls == ["expire", "sign-in-and-out"]
        assert "RP sign-in and sign-out:" in capsys.readouterr().out

    def test_driver_failure_is_reported_not_raised(self, hooks, capsys):
        def expire():
            raise hooks.HookError("no docker")

        hooks.run_rp_module("oidcc-client-test", "https://t.example/login", expire=expire)
        assert "could not be driven: no docker" in capsys.readouterr().out


class _FakeHttpResponse:
    def __init__(self, status_code, location=None, text=""):
        self.status_code = status_code
        self.headers = {"location": location} if location else {}
        self.is_redirect = location is not None and 300 <= status_code < 400
        self.text = text


class _FakeHttpClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.urls: list[str] = []
        self.posts: list[tuple[str, dict]] = []
        self.closed = False

    def get(self, url, follow_redirects=False):
        assert follow_redirects is False
        self.urls.append(url)
        return self._responses.pop(0)

    def post(self, url, data=None, follow_redirects=False):
        assert follow_redirects is False
        self.posts.append((url, data))
        return self._responses.pop(0)

    def close(self):
        self.closed = True


_DASHBOARD = '<head><meta name="csrf-token" content="tok&amp;1"></head>'
_LOGOUT_PAGE = (
    '<a id="logout-frontchannel-continue" '
    'href="https://op.example/end_session?id_token_hint=h&amp;state=s">Continue</a>'
)


class TestDriveRpLogout:
    def test_posts_logout_and_follows_the_provider_hop(self, hooks):
        client = _FakeHttpClient(
            [
                _FakeHttpResponse(200, text=_DASHBOARD),
                _FakeHttpResponse(200, text=_LOGOUT_PAGE),
                _FakeHttpResponse(302, "https://t.example/logout/complete?state=s"),
                _FakeHttpResponse(303, "/login"),
                _FakeHttpResponse(200),
            ]
        )
        hops = hooks.drive_rp_logout("https://t.example", client)
        assert client.urls[0] == "https://t.example/dashboard"
        assert client.posts == [("https://t.example/logout", {"csrf_token": "tok&1"})]
        assert client.urls[1] == "https://op.example/end_session?id_token_hint=h&state=s"
        assert client.urls[-1] == "https://t.example/login"
        assert hops[-1] == "HTTP 200"

    def test_not_signed_in_stops_before_posting(self, hooks):
        client = _FakeHttpClient([_FakeHttpResponse(303, "/login")])
        hops = hooks.drive_rp_logout("https://t.example", client)
        assert client.posts == []
        assert "not signed in" in hops[-1]

    def test_local_only_logout_is_reported(self, hooks):
        client = _FakeHttpClient(
            [_FakeHttpResponse(200, text=_DASHBOARD), _FakeHttpResponse(303, "/login")]
        )
        hops = hooks.drive_rp_logout("https://t.example", client)
        assert "no provider hop (HTTP 303)" in hops[-1]

    def test_sign_in_and_out_share_one_client(self, hooks):
        client = _FakeHttpClient(
            [
                _FakeHttpResponse(303, "/dashboard"),
                _FakeHttpResponse(200),
                _FakeHttpResponse(200, text=_DASHBOARD),
                _FakeHttpResponse(303, "/login"),
            ]
        )
        hops = hooks.drive_rp_login_and_logout("https://t.example/auth/oidc/c/login", client=client)
        assert client.urls[:3] == [
            "https://t.example/auth/oidc/c/login",
            "https://t.example/dashboard",
            "https://t.example/dashboard",
        ]
        assert "logout" in hops
        # A client passed in belongs to the caller.
        assert client.closed is False

    def test_own_client_is_closed_even_on_failure(self, hooks, monkeypatch):
        client = _FakeHttpClient([])  # the first GET fails (nothing queued)
        monkeypatch.setattr(hooks, "_new_client", lambda: client)
        with pytest.raises(IndexError):
            hooks.drive_rp_login_and_logout("https://t.example/auth/oidc/c/login")
        assert client.closed is True


class TestDriveRpLogin:
    def test_follows_redirects_across_hosts_until_a_page(self, hooks):
        client = _FakeHttpClient(
            [
                _FakeHttpResponse(303, "https://op.example:8443/test/a/rp/authorize?x=1"),
                _FakeHttpResponse(302, "https://t.example/auth/oidc/c/callback?code=1"),
                _FakeHttpResponse(303, "/dashboard"),
                _FakeHttpResponse(200),
            ]
        )
        hops = hooks.drive_rp_login("https://t.example/auth/oidc/c/login", client=client)
        assert client.urls[-1] == "https://t.example/dashboard"
        assert hops[-1] == "HTTP 200"
        assert len(hops) == 5

    def test_stops_after_max_hops(self, hooks):
        client = _FakeHttpClient([_FakeHttpResponse(302, "/loop")] * (hooks.MAX_RP_HOPS + 1))
        hops = hooks.drive_rp_login("https://t.example/loop", client=client)
        assert len(client.urls) == hooks.MAX_RP_HOPS
        assert len(hops) == hooks.MAX_RP_HOPS + 1


class TestTestbedCalls:
    def test_expire_rp_discovery(self, hooks):
        seen: list[list[str]] = []
        hooks.expire_rp_discovery(run=lambda cmd, **kw: seen.append(cmd) or _Result(0, "{}"))
        assert seen[0][-1] == "--expire-rp-discovery-flag"

    def test_expire_failure_raises(self, hooks):
        with pytest.raises(hooks.HookError, match="boom"):
            hooks.expire_rp_discovery(run=lambda cmd, **kw: _Result(1, stderr="boom"))

    def test_test_rp_connection(self, hooks):
        seen: list[list[str]] = []
        result = hooks.test_rp_connection(
            run=lambda cmd, **kw: seen.append(cmd) or _Result(0, '{"result": "success"}')
        )
        assert result == {"result": "success"}
        assert seen[0][-1] == "--test-rp-connection-flag"

    def test_test_rp_connection_failure_raises(self, hooks):
        with pytest.raises(hooks.HookError, match="boom"):
            hooks.test_rp_connection(run=lambda cmd, **kw: _Result(1, stderr="boom"))
