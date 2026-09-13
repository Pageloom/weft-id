"""Unit tests for the host-side OIDC conformance runner (dev/oidc_conformance.py).

Covers the pure parts: template rendering (placeholders, escaping, drift
detection), plan argument assembly, and the runner environment. The parts
that talk to Docker and the suite are exercised by ``make oidc-conformance``.
Also validates the checked-in template and expected-result files so a typo
fails here rather than as a baffling suite error.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "dev" / "oidc-conformance"


@pytest.fixture(scope="module")
def runner():
    src = PROJECT_ROOT / "dev" / "oidc_conformance.py"
    spec = importlib.util.spec_from_file_location("oidc_conformance_under_test", src)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["oidc_conformance_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def testbed() -> dict:
    return {
        "issuer": "https://oidc-conformance.weftid.localhost",
        "alias": "weftid",
        "user_email": "conformance-user@oidc-conformance.test",
        "password": 'p"ss\\word',  # quote and backslash must survive rendering
        "client1": {"client_id": "id1", "client_secret": "s1"},
        "client2": {"client_id": "id2", "client_secret": "s2"},
        "client3": {"client_id": "id3", "client_secret": "s3"},
    }


class TestRenderConfig:
    def test_checked_in_template_renders_to_valid_json(self, runner, testbed):
        rendered = runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed)
        cfg = json.loads(rendered)

        assert cfg["alias"] == "weftid"
        assert cfg["server"]["discoveryUrl"] == (
            "https://oidc-conformance.weftid.localhost/.well-known/openid-configuration"
        )
        assert cfg["client"] == {"client_id": "id1", "client_secret": "s1"}
        assert cfg["client2"] == {"client_id": "id2", "client_secret": "s2"}
        assert cfg["client_secret_post"] == {"client_id": "id3", "client_secret": "s3"}
        # No WeftID placeholder survives; braces left are the suite's own.
        for placeholder in runner.PLACEHOLDERS:
            assert placeholder not in rendered

    def test_special_characters_in_values_are_json_escaped(self, runner, testbed):
        rendered = runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed)
        cfg = json.loads(rendered)
        password_commands = [
            cmd
            for step in cfg["browser"][0]["tasks"]
            for cmd in step.get("commands", [])
            if cmd[0] == "text" and cmd[2] == "password"
        ]
        assert password_commands and password_commands[0][3] == 'p"ss\\word'

    def test_missing_testbed_value_is_an_error(self, runner, testbed):
        del testbed["client3"]
        with pytest.raises(runner.ConformanceError, match="client3.client_id"):
            runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed)

    def test_empty_testbed_value_is_an_error(self, runner, testbed):
        testbed["issuer"] = ""
        with pytest.raises(runner.ConformanceError, match="issuer"):
            runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed)

    def test_invalid_template_json_is_an_error(self, runner, testbed):
        with pytest.raises(json.JSONDecodeError):
            runner.render_config('{"issuer": "{WEFTID_ISSUER}",}', testbed)

    def test_suite_placeholders_are_left_for_the_suite(self, runner, testbed):
        template = '{"a": "{BASEURL}test/a/{ALIAS}/callback"}'
        rendered = runner.render_config(template, testbed)
        assert json.loads(rendered) == {"a": "{BASEURL}test/a/weftid/callback"}


class TestCheckedInFiles:
    def test_browser_automation_covers_every_login_step(self, runner, testbed):
        """Every optional interactive step is scripted so no test needs a human."""
        cfg = json.loads(runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed))
        tasks = {t["task"]: t for t in cfg["browser"][0]["tasks"]}
        assert {"Login: email step", "Login: password step", "Consent"} <= set(tasks)
        assert any(t.startswith("Login: MFA") for t in tasks)
        assert tasks["Consent"]["commands"] == [
            ["click", "css", "button[name='action'][value='allow']"]
        ]
        # The final task is mandatory and waits on the suite's own callback.
        final = cfg["browser"][0]["tasks"][-1]
        assert final["match"] == "*/test/*/callback*" and "optional" not in final

    @pytest.mark.parametrize("name", ["expected-failures.json", "expected-skips.json"])
    def test_expected_files_are_lists_of_complete_entries(self, name):
        entries = json.loads((CONFIG_DIR / name).read_text())
        assert isinstance(entries, list)
        required = {"test-name", "variant", "configuration-filename"}
        if name == "expected-failures.json":
            required |= {"current-block", "condition", "expected-result", "comment"}
        for entry in entries:
            assert required <= set(entry), f"{name}: incomplete entry {entry}"
            assert entry["configuration-filename"], f"{name}: empty configuration-filename"
            if "expected-result" in entry:
                assert entry["expected-result"] in ("failure", "warning")


class TestPlanArguments:
    def test_pairs_each_plan_with_the_config(self, runner):
        args = runner.plan_arguments(("plan-a[x=y]", "plan-b"), Path("/tmp/c.json"))
        assert args == ["plan-a[x=y]", "/tmp/c.json", "plan-b", "/tmp/c.json"]

    def test_default_plans_cover_the_three_in_scope_profiles(self, runner):
        joined = " ".join(runner.PLANS)
        assert "oidcc-basic-certification-test-plan[" in joined
        assert "oidcc-config-certification-test-plan" in joined
        assert "oidcc-formpost-basic-certification-test-plan[" in joined
        # Static clients are what the testbed provisions.
        assert "[client_registration=static_client]" in joined
        assert "dynamic_client" not in joined


class TestRunnerEnvironment:
    def test_dev_mode_and_ssl_bypass_for_local_suite(self, runner):
        env = runner.runner_environment({"PATH": "/bin"})
        assert env["PATH"] == "/bin"
        assert env["CONFORMANCE_SERVER"] == runner.SUITE_BASE_URL
        assert env["CONFORMANCE_DEV_MODE"] == "1"
        assert env["DISABLE_SSL_VERIFY"] == "1"
        assert env["CONFORMANCE_MAX_CONSECUTIVE_FAILURES"] == "1000"

    def test_caller_can_override_circuit_breaker(self, runner):
        env = runner.runner_environment({"CONFORMANCE_MAX_CONSECUTIVE_FAILURES": "3"})
        assert env["CONFORMANCE_MAX_CONSECUTIVE_FAILURES"] == "3"


class TestEnsureRunnerScripts:
    def test_downloads_once_per_tag_and_reuses(self, runner, tmp_path, monkeypatch):
        fetched: list[str] = []

        class _Resp:
            def __init__(self, url):
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return f"# {self.url}\n".encode()

        monkeypatch.setattr(
            runner.urllib.request, "urlopen", lambda url, timeout: fetched.append(url) or _Resp(url)
        )

        scripts = runner.ensure_runner_scripts(tmp_path, "release-v9.9.9")
        assert len(fetched) == len(runner.RUNNER_SCRIPTS)
        assert all(("release-v9.9.9" in u) for u in fetched)
        assert (scripts / "run-test-plan.py").exists()
        assert (scripts / "certs-keys").is_dir()

        # Same tag: nothing re-fetched.
        runner.ensure_runner_scripts(tmp_path, "release-v9.9.9")
        assert len(fetched) == len(runner.RUNNER_SCRIPTS)

        # New tag: replaced.
        runner.ensure_runner_scripts(tmp_path, "release-v10.0.0")
        assert len(fetched) == 2 * len(runner.RUNNER_SCRIPTS)
        assert (scripts / ".suite-tag").read_text().strip() == "release-v10.0.0"

    def test_download_failure_is_reported(self, runner, tmp_path, monkeypatch):
        def _boom(url, timeout):
            raise OSError("no network")

        monkeypatch.setattr(runner.urllib.request, "urlopen", _boom)
        with pytest.raises(runner.ConformanceError, match="could not download"):
            runner.ensure_runner_scripts(tmp_path, "release-v9.9.9")


class TestRateLimitReset:
    def test_flushes_on_entry_and_periodically_then_stops(self, runner):
        import time

        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)

        with runner.RateLimitReset(interval=0.01, run=fake_run) as reset:
            time.sleep(0.08)
        assert reset.flushes >= 3
        assert all(cmd == runner.FLUSH_COMMAND for cmd in calls)
        assert "flush_all" in runner.FLUSH_COMMAND[-1] and "memcached" in runner.FLUSH_COMMAND
        # Stopped: no further flushes after exit.
        settled = reset.flushes
        time.sleep(0.05)
        assert reset.flushes == settled

    def test_flush_failure_warns_once_and_continues(self, runner, capsys):
        import time

        def failing_run(cmd, **kwargs):
            raise OSError("docker is gone")

        with runner.RateLimitReset(interval=0.01, run=failing_run) as reset:
            time.sleep(0.05)
        assert reset.flushes == 0
        err = capsys.readouterr().err
        assert err.count("could not flush memcached") == 1


class TestCli:
    def test_render_subcommand_writes_config_to_stdout(self, runner, testbed, tmp_path, capsys):
        testbed_file = tmp_path / "testbed.json"
        testbed_file.write_text(json.dumps(testbed))
        assert runner.main(["render", "--testbed-json", str(testbed_file)]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["client"]["client_id"] == "id1"

    def test_run_requires_the_suite_runtime(self, runner, tmp_path):
        with pytest.raises(runner.ConformanceError, match="oidc-conformance-up"):
            runner.main(["run", "--runtime-dir", str(tmp_path)])
