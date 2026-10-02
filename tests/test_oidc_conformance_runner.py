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
        "client4": {"client_id": "id4", "client_secret": "s4"},
        "client5": {"client_id": "id5", "client_secret": "s5"},
        "client6": {"client_id": "id6", "jwks": {"keys": [{"kty": "RSA", "kid": "k6", "d": "x"}]}},
        "client7": {"client_id": "id7", "jwks": {"keys": [{"kty": "RSA", "kid": "k7", "d": "y"}]}},
        "initial_access_token": "weft-id_iat_abc",
        "rp": {
            "alias": "weftid-rp",
            "client_id": "weftid-rp-conformance",
            "client_secret": 'rp-s"ecret',
            "redirect_uri": "https://oidc-conformance.weftid.localhost/auth/oidc/c1/callback",
            "login_url": "https://oidc-conformance.weftid.localhost/auth/oidc/c1/login",
            "post_logout_redirect_uri": "https://oidc-conformance.weftid.localhost/logout/complete",
            "backchannel_logout_uri": (
                "https://oidc-conformance.weftid.localhost/auth/oidc/c1/backchannel-logout"
            ),
        },
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
        # Only the front-channel module uses the client registered with a
        # frontchannel_logout_uri.
        assert cfg["override"]["oidcc-frontchannel-rp-initiated-logout"] == {
            "client": {"client_id": "id4", "client_secret": "s4"}
        }
        # Likewise the back-channel module and its backchannel_logout_uri client.
        assert cfg["override"]["oidcc-backchannel-rp-initiated-logout"] == {
            "client": {"client_id": "id5", "client_secret": "s5"}
        }
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


class TestBrowserRefs:
    def _config(self, *override_entries) -> dict:
        return {
            "browser": [{"match": "a*"}, {"match": "b*"}],
            "override": {"mod": {"browser": list(override_entries)}},
        }

    def test_references_become_copies_of_top_level_entries(self, runner):
        cfg = self._config("$browser[1]", {"match": "c*"}, "$browser[0]")
        expanded = runner.expand_browser_refs(cfg)
        assert expanded["override"]["mod"]["browser"] == [
            {"match": "b*"},
            {"match": "c*"},
            {"match": "a*"},
        ]
        # A copy, not an alias, and the input is left alone.
        assert expanded["override"]["mod"]["browser"][0] is not expanded["browser"][1]
        assert cfg["override"]["mod"]["browser"][0] == "$browser[1]"

    @pytest.mark.parametrize("bad", ["$browser[2]", "$browser[x]", "browser[0]", "$browser"])
    def test_bad_reference_is_an_error(self, runner, bad):
        with pytest.raises(runner.ConformanceError, match="mod"):
            runner.expand_browser_refs(self._config(bad))

    def test_overrides_without_browser_are_untouched(self, runner):
        cfg = {"browser": [], "override": {"mod": {"skip": True}, "other": "x"}}
        assert runner.expand_browser_refs(cfg) == cfg

    def test_template_without_references_renders_byte_for_byte(self, runner, testbed):
        template = '{"alias": "{ALIAS}", "override": {"m": {"browser": [{"match": "x"}]}}}'
        rendered = runner.render_config(template, testbed)
        assert rendered == template.replace("{ALIAS}", "weftid")

    def test_render_expands_references(self, runner, testbed):
        template = (
            '{"browser": [{"match": "{WEFTID_ISSUER}/x"}],'
            ' "override": {"m": {"browser": ["$browser[0]"]}}}'
        )
        cfg = json.loads(runner.render_config(template, testbed))
        assert cfg["override"]["m"]["browser"] == [{"match": f"{testbed['issuer']}/x"}]


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

    def test_logout_automation(self, runner, testbed):
        """The end-session entry confirms, snapshots the signed-out page, and
        accepts the redirect back; the confirmation-page modules snapshot
        that page instead and keep the full login script."""
        cfg = json.loads(runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed))
        issuer = testbed["issuer"]
        logout = next(e for e in cfg["browser"] if e["match"] == f"{issuer}/oauth2/logout*")
        tasks = {t["task"]: t for t in logout["tasks"]}
        assert all(t.get("optional") for t in logout["tasks"])
        assert tasks["Confirm sign-out"]["commands"][0][-1] == "optional"
        assert tasks["Signed-out page"]["match"] == f"{issuer}/oauth2/logout/done*"

        confirm_modules = [
            "oidcc-rp-initiated-logout-bad-id-token-hint",
            "oidcc-rp-initiated-logout-modified-id-token-hint",
            "oidcc-rp-initiated-logout-no-id-token-hint",
            "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
            "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
        ]
        for name in confirm_modules:
            browser = cfg["override"][name]["browser"]
            assert browser[0] == cfg["browser"][0], f"{name}: login script not expanded"
            (task,) = browser[1]["tasks"]
            assert task["commands"] == [
                ["wait", "id", "logout-confirm", 10, "Sign out", "update-image-placeholder"]
            ]

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

    def test_default_plans_cover_the_in_scope_profiles(self, runner):
        joined = " ".join(runner.PLANS)
        assert "oidcc-basic-certification-test-plan[" in joined
        assert "oidcc-config-certification-test-plan" in joined
        assert "oidcc-formpost-basic-certification-test-plan[" in joined
        assert (
            "oidcc-rp-initiated-logout-certification-test-plan"
            "[response_type=code][client_registration=static_client]"
        ) in runner.PLANS
        assert (
            "oidcc-frontchannel-rp-initiated-logout-certification-test-plan"
            "[response_type=code][client_registration=static_client]"
        ) in runner.PLANS
        assert (
            "oidcc-backchannel-rp-initiated-logout-certification-test-plan"
            "[response_type=code][client_registration=static_client]"
        ) in runner.PLANS
        # Static clients are what the testbed provisions.
        assert "[client_registration=static_client]" in joined
        assert "dynamic_client" not in joined

    def test_dynamic_plans_cover_dynamic_op_and_third_party_initiated_login(self, runner):
        assert runner.DYNAMIC_PLANS == (
            "oidcc-dynamic-certification-test-plan[response_type=code]",
            "oidcc-3rdparty-init-login-certification-test-plan[response_type=code]",
        )

    def test_private_key_jwt_plan_uses_static_clients(self, runner):
        (plan,) = runner.PRIVATE_KEY_JWT_PLANS
        assert plan.startswith("oidcc-test-plan[")
        assert "[client_auth_type=private_key_jwt]" in plan
        assert "[client_registration=static_client]" in plan
        assert "[response_type=code]" in plan


def _derived(runner, template_path, testbed) -> dict:
    static = runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed)
    return json.loads(runner.render_derived_config(template_path.read_text(), static, testbed))


class TestObjectPlaceholders:
    def test_object_value_replaces_the_quoted_placeholder(self, runner, testbed):
        cfg = json.loads(
            runner.render_config('{"jwks": "{CLIENT6_JWKS}", "id": "{CLIENT6_ID}"}', testbed)
        )
        assert cfg == {"jwks": testbed["client6"]["jwks"], "id": "id6"}

    def test_empty_object_is_an_error(self, runner, testbed):
        testbed["client6"]["jwks"] = {}
        with pytest.raises(runner.ConformanceError, match="client6.jwks"):
            runner.render_config("{}", testbed)

    def test_other_value_types_are_an_error(self, runner, testbed):
        testbed["client6"]["jwks"] = ["not", "an", "object"]
        with pytest.raises(runner.ConformanceError, match="non-empty string or object"):
            runner.render_config("{}", testbed)


class TestInheritStatic:
    STATIC = {
        "options": {"browsercontrol_css_enable": False},
        "browser": [{"match": "login"}],
        "client": {"client_id": "static"},
        "override": {
            "error-page": {"browser": [{"match": "error"}]},
            "swaps-client": {"client": {"client_id": "other"}},
            "both": {"client": {"client_id": "other"}, "browser": []},
            "shared": {"browser": [{"match": "static"}]},
        },
    }

    def test_inherits_options_browser_and_browser_only_overrides(self, runner):
        merged = runner.inherit_static({"client": {"client_id": "mine"}}, self.STATIC)
        assert merged["options"] == self.STATIC["options"]
        assert merged["browser"] == self.STATIC["browser"]
        assert merged["client"] == {"client_id": "mine"}
        assert set(merged["override"]) == {"error-page", "shared"}

    def test_own_keys_and_overrides_win(self, runner):
        own = {
            "browser": [{"match": "own"}],
            "override": {"shared": {"browser": [{"match": "own"}]}, "mine": {"browser": []}},
        }
        merged = runner.inherit_static(own, self.STATIC)
        assert merged["browser"] == [{"match": "own"}]
        assert merged["override"]["shared"] == {"browser": [{"match": "own"}]}
        assert set(merged["override"]) == {"error-page", "shared", "mine"}

    def test_inputs_are_not_mutated(self, runner):
        static = json.loads(json.dumps(self.STATIC))
        own: dict = {}
        merged = runner.inherit_static(own, static)
        merged["browser"].append("x")
        assert own == {}
        assert static == self.STATIC

    def test_no_overrides_key_when_nothing_to_inherit(self, runner):
        assert "override" not in runner.inherit_static({}, {"browser": []})

    def test_references_expand_against_the_inherited_browser(self, runner, testbed):
        template = json.dumps({"override": {"m": {"browser": ["$browser[1]"]}}})
        static = runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed)
        cfg = json.loads(runner.render_derived_config(template, static, testbed))
        assert cfg["override"]["m"]["browser"] == [json.loads(static)["browser"][1]]


class TestPrivateKeyJwtConfig:
    def test_clients_carry_their_private_jwks(self, runner, testbed):
        cfg = _derived(runner, runner.PRIVATE_KEY_JWT_TEMPLATE_PATH, testbed)
        assert cfg["client"] == {"client_id": "id6", "jwks": testbed["client6"]["jwks"]}
        assert cfg["client2"] == {"client_id": "id7", "jwks": testbed["client7"]["jwks"]}
        assert "client_secret_post" not in cfg
        # Same alias as the static plans: the clients use the same callback URL.
        assert cfg["alias"] == "weftid"

    def test_inherits_the_login_automation_but_not_the_logout_clients(self, runner, testbed):
        cfg = _derived(runner, runner.PRIVATE_KEY_JWT_TEMPLATE_PATH, testbed)
        static = json.loads(runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed))
        assert cfg["options"] == static["options"]
        assert cfg["browser"] == static["browser"]
        assert cfg["override"]["oidcc-prompt-login"] == static["override"]["oidcc-prompt-login"]
        assert "oidcc-frontchannel-rp-initiated-logout" not in cfg["override"]
        assert "oidcc-backchannel-rp-initiated-logout" not in cfg["override"]


class TestDynamicConfig:
    def test_dynamic_template_carries_the_initial_access_token(self, runner, testbed):
        cfg = _derived(runner, runner.DYNAMIC_TEMPLATE_PATH, testbed)
        assert cfg["server"]["discoveryUrl"] == (
            "https://oidc-conformance.weftid.localhost/.well-known/openid-configuration"
        )
        assert cfg["client"]["initial_access_token"] == "weft-id_iat_abc"
        assert cfg["client"]["client_name"]
        # A different alias from the static plans: no clash of callback URLs.
        assert cfg["alias"] != "weftid"
        assert "client_id" not in cfg["client"]

    def test_inherits_the_login_automation(self, runner, testbed):
        cfg = _derived(runner, runner.DYNAMIC_TEMPLATE_PATH, testbed)
        static = json.loads(runner.render_config(runner.TEMPLATE_PATH.read_text(), testbed))
        assert cfg["options"] == static["options"]
        assert cfg["browser"] == static["browser"]
        assert "oidcc-redirect-uri-query-added" in cfg["override"]

    @pytest.mark.parametrize(
        ("module", "element"),
        [
            ("oidcc-registration-logo-uri", "client-logo"),
            ("oidcc-registration-policy-uri", "client-policy"),
            ("oidcc-registration-tos-uri", "client-tos"),
        ],
    )
    def test_review_modules_snapshot_the_consent_page(self, runner, testbed, module, element):
        cfg = _derived(runner, runner.DYNAMIC_TEMPLATE_PATH, testbed)
        (entry,) = cfg["override"][module]["browser"]
        tasks = {task["task"]: task for task in entry["tasks"]}
        consent = next(t for name, t in tasks.items() if name.startswith("Consent"))
        # Required, not optional: the module must fail loudly if the page lacks it.
        assert not consent.get("optional")
        assert consent["commands"][0] == ["wait", "id", element, 10]
        assert consent["commands"][1][-1] == "update-image-placeholder"
        # The filled placeholder ends the module. Consenting would race the
        # callback against the module's end, so the script stops here.
        assert len(consent["commands"]) == 2
        assert entry["tasks"][-1] is consent

    def test_missing_initial_access_token_is_an_error(self, runner, testbed):
        del testbed["initial_access_token"]
        with pytest.raises(runner.ConformanceError, match="initial_access_token"):
            runner.render_config(runner.DYNAMIC_TEMPLATE_PATH.read_text(), testbed)

    def test_configs_are_written_private_and_match_the_expected_files_glob(self, runner, tmp_path):
        static = runner.write_config(tmp_path, "{}")
        dynamic = runner.write_config(tmp_path, "{}", name="dynamic-config.json")
        pkjwt = runner.write_config(tmp_path, "{}", name="private-key-jwt-config.json")
        assert static.name == "config.json"
        assert dynamic.name == "dynamic-config.json"
        for path in (static, dynamic, pkjwt):
            # The expected-failures/skips entries match by "*config.json".
            assert path.name.endswith("config.json")
            assert path.stat().st_mode & 0o777 == 0o600


class TestRunPlans:
    def test_runs_every_plan_group_through_the_hooks_wrapper(self, runner, tmp_path, monkeypatch):
        calls: list[tuple[list[str], dict]] = []

        class _Done:
            returncode = 3

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return _Done()

        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        rc = runner.run_plans(
            tmp_path,
            [(("a", "b"), Path("/c/config.json")), (("d",), Path("/c/dynamic-config.json"))],
            tmp_path / "export",
            ["--verbose"],
        )
        assert rc == 3
        (cmd, kwargs) = next(c for c in calls if str(runner.HOOKS_SCRIPT) in c[0])
        assert cmd[1] == str(runner.HOOKS_SCRIPT)
        assert kwargs["cwd"] == tmp_path
        # Serial: a key rotation must never overlap another plan's module.
        assert "--no-parallel" in cmd
        assert cmd[-7:] == [
            "--verbose",
            "a",
            "/c/config.json",
            "b",
            "/c/config.json",
            "d",
            "/c/dynamic-config.json",
        ]
        assert (tmp_path / "export").is_dir()


class TestRpConfig:
    def test_rp_template_renders_the_static_client(self, runner, testbed):
        cfg = json.loads(runner.render_config(runner.RP_TEMPLATE_PATH.read_text(), testbed))
        assert cfg["alias"] == "weftid-rp"
        assert cfg["client"] == {
            "client_id": "weftid-rp-conformance",
            "client_secret": 'rp-s"ecret',
            "redirect_uri": "https://oidc-conformance.weftid.localhost/auth/oidc/c1/callback",
            "post_logout_redirect_uri": "https://oidc-conformance.weftid.localhost/logout/complete",
            "backchannel_logout_uri": (
                "https://oidc-conformance.weftid.localhost/auth/oidc/c1/backchannel-logout"
            ),
        }
        # Negative modules end this long after the RP stops calling.
        assert cfg["waitTimeoutSeconds"] == 5

    def test_rp_plans_cover_basic_config_and_logout_rp(self, runner):
        names = [plan.split("[", 1)[0] for plan in runner.RP_PLANS]
        assert names == [
            "oidcc-client-basic-certification-test-plan",
            "oidcc-client-config-certification-test-plan",
            "oidcc-client-rp-initiated-logout-rp-basic",
            "oidcc-client-back-channel-logout-rp-basic",
        ]
        assert all("[client_registration=static_client]" in plan for plan in runner.RP_PLANS)
        for plan in runner.RP_PLANS[2:]:
            assert "[client_auth_type=client_secret_basic]" in plan
            assert "[response_mode=default]" in plan

    def test_missing_rp_section_is_an_error(self, runner, testbed):
        del testbed["rp"]
        with pytest.raises(runner.ConformanceError, match="rp.alias"):
            runner.render_config(runner.RP_TEMPLATE_PATH.read_text(), testbed)

    def test_rp_config_matches_the_expected_files_glob(self, runner, tmp_path):
        import fnmatch

        path = runner.write_config(tmp_path, "{}", name="rp-config.json")
        skips = json.loads(runner.EXPECTED_SKIPS_PATH.read_text())
        rp_entries = [e for e in skips if e["test-name"].startswith("oidcc-client-test")]
        assert rp_entries
        for entry in rp_entries:
            assert fnmatch.fnmatch(str(path), entry["configuration-filename"])
            # ...and not the OP plans' configs.
            assert not fnmatch.fnmatch("/x/config.json", entry["configuration-filename"])


class TestRunnerEnvironment:
    def test_rp_login_url_is_passed_to_the_hooks(self, runner):
        env = runner.runner_environment({}, "https://t.example/auth/oidc/c/login")
        assert env["WEFTID_RP_LOGIN_URL"] == "https://t.example/auth/oidc/c/login"
        assert "WEFTID_RP_LOGIN_URL" not in runner.runner_environment({})

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
