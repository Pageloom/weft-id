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
