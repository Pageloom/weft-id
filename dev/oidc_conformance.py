#!/usr/bin/env python3
"""Run the OpenID Foundation conformance suite against WeftID's OpenID Provider.

Host-side runner behind ``make oidc-conformance``. It expects the dev stack
(``make up``) and the suite (``make oidc-conformance-up``) to be running, then:

1. downloads the suite's ``run-test-plan.py`` and its two helper modules for
   the pinned release into the suite runtime directory (once per release),
2. provisions the conformance tenant, user and static clients by running
   ``app/dev/oidc_conformance_testbed.py`` inside the app container,
3. renders ``dev/oidc-conformance/config.template.json`` (static-client
   plans) and ``config-dynamic.template.json`` (plans that register their
   own clients) with the testbed's values into the runtime directory (never
   into the repo: they hold secrets),
4. runs the certification plans through ``run-test-plan.py`` with the
   checked-in expected-failures and expected-skips files and exports the
   results to ``dev/oidc-conformance/export/``.

The exit code is the runner's: zero only when every module finished and the
outcome matches the expected files exactly (including no unused entries).

Usage:
    poetry run python dev/oidc_conformance.py run [--list] [--verbose] [...]
    poetry run python dev/oidc_conformance.py render --testbed-json <file>

Any argument not recognised here is passed through to ``run-test-plan.py``
(for example ``--no-parallel``, ``--rerun 2:6``, ``--verbose``).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "dev" / "oidc-conformance"
TEMPLATE_PATH = CONFIG_DIR / "config.template.json"
DYNAMIC_TEMPLATE_PATH = CONFIG_DIR / "config-dynamic.template.json"
EXPECTED_FAILURES_PATH = CONFIG_DIR / "expected-failures.json"
EXPECTED_SKIPS_PATH = CONFIG_DIR / "expected-skips.json"
DEFAULT_EXPORT_DIR = CONFIG_DIR / "export"

DEFAULT_RUNTIME_DIR = Path.home() / ".local" / "share" / "weft-id" / "oidc-conformance"
# Keep in step with DEFAULT_TAG in dev/oidc-conformance.sh.
DEFAULT_SUITE_TAG = "release-v5.2.4"
SUITE_BASE_URL = "https://localhost.emobix.co.uk:8443"
SUITE_RAW_URL = "https://gitlab.com/openid/conformance-suite/-/raw/{tag}/scripts/{name}"
# run-test-plan.py imports the other two as plain modules from its own dir.
RUNNER_SCRIPTS = ("run-test-plan.py", "conformance.py", "test_plan_parser.py")

TESTBED_SCRIPT = "./dev/oidc_conformance_testbed.py"
DOCKER_COMPOSE = [
    "docker",
    "compose",
    "--project-directory",
    str(PROJECT_ROOT),
    "-f",
    str(PROJECT_ROOT / "dev" / "docker-compose.yml"),
]
# WeftID rate-limits the login steps (email routing per IP, MFA verify per
# user: five attempts per fifteen minutes). A plan logs the same user in from
# one IP once per module, and modules that fail early take about a second
# each, so a burst of six attempts inside one flush window is realistic.
# Rather than weaken the product for the harness, the run resets the counters
# by flushing memcached (where the limits live) once a second, the same way
# the E2E fixtures do before each testbed. Nothing else the flow depends on is
# cached: OTP passes via BYPASS_OTP, sessions are cookies, codes and tokens
# live in Postgres.
FLUSH_INTERVAL_SECONDS = 1.0
FLUSH_COMMAND = [
    *DOCKER_COMPOSE,
    "exec",
    "-T",
    "memcached",
    "sh",
    "-c",
    'echo "flush_all" | nc localhost 11211',
]

# Plans and variants for the profiles in scope. Names follow the suite's own
# CI script (.gitlab-ci/run-tests.sh). Each entry is one argument pair for
# run-test-plan.py: "<plan-name>[variants] <config-file>".
PLANS = (
    "oidcc-basic-certification-test-plan"
    "[server_metadata=discovery][client_registration=static_client]",
    "oidcc-config-certification-test-plan",
    "oidcc-formpost-basic-certification-test-plan"
    "[server_metadata=discovery][client_registration=static_client]",
    "oidcc-rp-initiated-logout-certification-test-plan"
    "[response_type=code][client_registration=static_client]",
    "oidcc-frontchannel-rp-initiated-logout-certification-test-plan"
    "[response_type=code][client_registration=static_client]",
    "oidcc-backchannel-rp-initiated-logout-certification-test-plan"
    "[response_type=code][client_registration=static_client]",
)

# Plans that register their own clients (dynamic client registration with the
# testbed's initial access token). They run with the dynamic config. The
# 3rd Party-Init OP plan fixes every variant except the response type.
DYNAMIC_PLANS = ("oidcc-3rdparty-init-login-certification-test-plan[response_type=code]",)

# An override's ``browser`` list may name a top-level browser entry as
# ``"$browser[N]"`` instead of repeating it. The suite replaces the whole list
# for an overridden module, so every override that still needs the login
# script would otherwise carry a full copy of it.
_BROWSER_REF = re.compile(r"^\$browser\[(\d+)\]$")

# Mapping from template placeholder to the testbed JSON path that fills it.
# Placeholders use the same ``{NAME}`` convention as run-test-plan.py's own
# substitutions (``{BASEURL}`` and friends), which it applies after ours.
PLACEHOLDERS = {
    "{WEFTID_ISSUER}": ("issuer",),
    "{ALIAS}": ("alias",),
    "{USER_EMAIL}": ("user_email",),
    "{USER_PASSWORD}": ("password",),
    "{CLIENT1_ID}": ("client1", "client_id"),
    "{CLIENT1_SECRET}": ("client1", "client_secret"),
    "{CLIENT2_ID}": ("client2", "client_id"),
    "{CLIENT2_SECRET}": ("client2", "client_secret"),
    "{CLIENT3_ID}": ("client3", "client_id"),
    "{CLIENT3_SECRET}": ("client3", "client_secret"),
    "{CLIENT4_ID}": ("client4", "client_id"),
    "{CLIENT4_SECRET}": ("client4", "client_secret"),
    "{CLIENT5_ID}": ("client5", "client_id"),
    "{CLIENT5_SECRET}": ("client5", "client_secret"),
    "{INITIAL_ACCESS_TOKEN}": ("initial_access_token",),
}


class ConformanceError(Exception):
    """A step of the run could not be completed."""


# ---------------------------------------------------------------------------
# Pure helpers (unit tested)
# ---------------------------------------------------------------------------


def _lookup(testbed: dict, path: tuple[str, ...]) -> str:
    value: object = testbed
    for key in path:
        if not isinstance(value, dict) or key not in value:
            raise ConformanceError(f"testbed output is missing '{'.'.join(path)}'")
        value = value[key]
    if not isinstance(value, str) or not value:
        raise ConformanceError(f"testbed value '{'.'.join(path)}' must be a non-empty string")
    return value


def render_config(template_text: str, testbed: dict) -> str:
    """Fill the plan config template with the testbed's values.

    Every WeftID placeholder must be consumed; a leftover one means the
    template and the testbed drifted apart, which would only surface as a
    baffling suite failure. Placeholders the suite substitutes itself
    (``{BASEURL}`` etc.) are left untouched. Values are inserted as JSON
    string fragments so a secret containing a quote cannot break the file.
    """
    rendered = template_text
    for placeholder, path in PLACEHOLDERS.items():
        value = _lookup(testbed, path)
        # json.dumps wraps in quotes; strip them since the placeholder sits
        # inside an existing JSON string literal.
        fragment = json.dumps(value)[1:-1]
        rendered = rendered.replace(placeholder, fragment)

    leftover = [p for p in PLACEHOLDERS if p in rendered]
    if leftover:
        raise ConformanceError(f"unrendered placeholders: {', '.join(leftover)}")

    # Must still be valid JSON (catches a template typo before the suite does).
    config = json.loads(rendered)
    if not _has_browser_refs(config):
        return rendered
    return json.dumps(expand_browser_refs(config), indent=4) + "\n"


def _has_browser_refs(config: dict) -> bool:
    overrides = config.get("override") or {}
    return any(
        isinstance(entry, str)
        for module in overrides.values()
        if isinstance(module, dict)
        for entry in module.get("browser") or []
    )


def expand_browser_refs(config: dict) -> dict:
    """Replace ``"$browser[N]"`` entries in override browser lists.

    Each reference becomes a copy of the config's top-level ``browser[N]``.
    Any other string, or an index out of range, is an error: the suite would
    reject the entry or, worse, silently drive the wrong page.
    """
    top_level = config.get("browser") or []
    expanded = copy.deepcopy(config)
    for name, module in (expanded.get("override") or {}).items():
        if not isinstance(module, dict) or "browser" not in module:
            continue
        entries = []
        for entry in module["browser"]:
            if not isinstance(entry, str):
                entries.append(entry)
                continue
            match = _BROWSER_REF.match(entry)
            if not match or int(match.group(1)) >= len(top_level):
                raise ConformanceError(f"override '{name}': bad browser reference {entry!r}")
            entries.append(copy.deepcopy(top_level[int(match.group(1))]))
        module["browser"] = entries
    return expanded


def plan_arguments(plans: tuple[str, ...], config_path: Path) -> list[str]:
    """Build the positional ``<plan> <config>`` pairs for run-test-plan.py."""
    args: list[str] = []
    for plan in plans:
        args.extend([plan, str(config_path)])
    return args


def runner_environment(base_env: dict[str, str]) -> dict[str, str]:
    """Environment for run-test-plan.py against the local dev-mode suite."""
    env = dict(base_env)
    env["CONFORMANCE_SERVER"] = SUITE_BASE_URL
    # The suite runs with SPRING_PROFILES_ACTIVE=dev: no API token, and the
    # runner skips TLS verification of the suite's self-signed nginx cert.
    env["CONFORMANCE_DEV_MODE"] = "1"
    env["DISABLE_SSL_VERIFY"] = "1"
    # The runner aborts the whole run after N consecutive modules fail to
    # complete, which is meant to catch a dead suite. A WeftID gap that leaves
    # a module INTERRUPTED counts too, and a plan for an unsupported feature
    # (form_post before Iteration 4) is one long streak of those. Effectively
    # disable the breaker: we want the full punch list, and a dead suite fails
    # each module in seconds anyway.
    env.setdefault("CONFORMANCE_MAX_CONSECUTIVE_FAILURES", "1000")
    return env


class RateLimitReset:
    """Context manager that flushes memcached on entry and every ``interval``.

    ``run`` is injectable for tests. Flush failures are reported once and do
    not abort the run: the suite will surface the resulting rate-limit
    failures loudly enough on its own.
    """

    def __init__(self, interval: float = FLUSH_INTERVAL_SECONDS, run=subprocess.run):
        self._interval = interval
        self._run = run
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._warned = False
        self.flushes = 0

    def _flush(self) -> None:
        try:
            self._run(FLUSH_COMMAND, capture_output=True, timeout=10)
            self.flushes += 1
        except Exception as exc:  # noqa: BLE001 - keep the run going
            if not self._warned:
                print(f"warning: could not flush memcached rate limits: {exc}", file=sys.stderr)
                self._warned = True

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            self._flush()

    def __enter__(self) -> RateLimitReset:
        self._flush()
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> bool:
        self._stop.set()
        self._thread.join(timeout=self._interval + 10)
        return False


# ---------------------------------------------------------------------------
# Steps with side effects
# ---------------------------------------------------------------------------


def ensure_runner_scripts(runtime_dir: Path, tag: str) -> Path:
    """Download the suite's runner scripts for ``tag`` unless already present."""
    scripts_dir = runtime_dir / "scripts"
    stamp = scripts_dir / ".suite-tag"
    if (
        stamp.exists()
        and stamp.read_text().strip() == tag
        and all((scripts_dir / name).exists() for name in RUNNER_SCRIPTS)
    ):
        return scripts_dir

    if scripts_dir.exists():
        shutil.rmtree(scripts_dir)
    scripts_dir.mkdir(parents=True)
    # run-test-plan.py reads every file in ./certs-keys/ next to itself.
    (scripts_dir / "certs-keys").mkdir()

    for name in RUNNER_SCRIPTS:
        url = SUITE_RAW_URL.format(tag=tag, name=name)
        print(f"Fetching {url}")
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - fixed https host
                (scripts_dir / name).write_bytes(resp.read())
        except OSError as exc:
            raise ConformanceError(f"could not download {url}: {exc}") from exc
    stamp.write_text(tag + "\n")
    return scripts_dir


def provision_testbed(alias: str) -> dict:
    """Run the testbed script inside the app container and parse its JSON."""
    cmd = [
        *DOCKER_COMPOSE,
        "exec",
        "-T",
        "app",
        "python",
        TESTBED_SCRIPT,
        "--json-output",
        "--suite-base-url",
        SUITE_BASE_URL,
        "--alias",
        alias,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise ConformanceError(
            f"testbed provisioning failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ConformanceError(f"testbed output is not JSON: {result.stdout!r}") from exc


def write_config(runtime_dir: Path, rendered: str, name: str = "config.json") -> Path:
    # Keep the name ending in config.json: the expected-failures and
    # expected-skips entries match configurations by "*config.json".
    config_path = runtime_dir / name
    config_path.write_text(rendered)
    config_path.chmod(0o600)
    return config_path


def run_plans(
    scripts_dir: Path,
    config_path: Path,
    dynamic_config_path: Path,
    export_dir: Path,
    passthrough: list[str],
) -> int:
    export_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(scripts_dir / "run-test-plan.py"),
        "--export-dir",
        str(export_dir),
        "--expected-failures-file",
        str(EXPECTED_FAILURES_PATH),
        "--expected-skips-file",
        str(EXPECTED_SKIPS_PATH),
        *passthrough,
        *plan_arguments(PLANS, config_path),
        *plan_arguments(DYNAMIC_PLANS, dynamic_config_path),
    ]
    print("Running:", " ".join(cmd))
    # cwd matters: the runner resolves ./certs-keys relative to itself but
    # some helper paths relative to the working directory.
    with RateLimitReset() as reset:
        completed = subprocess.run(cmd, cwd=scripts_dir, env=runner_environment(dict(os.environ)))
    print(f"(reset WeftID rate limits {reset.flushes} times during the run)")
    return completed.returncode


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="provision, render, and run the plans")
    run.add_argument(
        "--runtime-dir",
        type=Path,
        default=None,
        help="suite runtime dir (default: $OIDC_CONFORMANCE_DIR or "
        "~/.local/share/weft-id/oidc-conformance)",
    )
    run.add_argument(
        "--suite-tag",
        default=None,
        help="suite release tag (default: $OIDC_CONFORMANCE_TAG or the pinned release)",
    )
    run.add_argument("--export-dir", type=Path, default=DEFAULT_EXPORT_DIR)
    run.add_argument(
        "--alias", default="weftid", help="suite test-instance alias (callback path component)"
    )

    render = sub.add_parser(
        "render", help="render the config template to stdout from a testbed JSON file"
    )
    render.add_argument("--testbed-json", type=Path, required=True)

    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    args, passthrough = _parse_args(sys.argv[1:] if argv is None else argv)

    if args.command == "render":
        testbed = json.loads(args.testbed_json.read_text())
        sys.stdout.write(render_config(TEMPLATE_PATH.read_text(), testbed))
        return 0

    runtime_dir = args.runtime_dir or Path(
        os.environ.get("OIDC_CONFORMANCE_DIR", str(DEFAULT_RUNTIME_DIR))
    )
    tag = args.suite_tag or os.environ.get("OIDC_CONFORMANCE_TAG", DEFAULT_SUITE_TAG)
    if not (runtime_dir / "compose.yml").exists():
        raise ConformanceError(
            f"no conformance suite at {runtime_dir}; run 'make oidc-conformance-up' first"
        )

    scripts_dir = ensure_runner_scripts(runtime_dir, tag)
    testbed = provision_testbed(args.alias)
    config_path = write_config(runtime_dir, render_config(TEMPLATE_PATH.read_text(), testbed))
    dynamic_config_path = write_config(
        runtime_dir,
        render_config(DYNAMIC_TEMPLATE_PATH.read_text(), testbed),
        name="dynamic-config.json",
    )
    print(f"Rendered plan configs to {runtime_dir} (issuer {testbed['issuer']})")
    return run_plans(
        scripts_dir, config_path, dynamic_config_path, args.export_dir, passthrough
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConformanceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
