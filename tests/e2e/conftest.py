"""E2E test fixtures for SAML SSO flows.

Uses Playwright to drive a real browser against two WeftId tenants
(one as IdP, one as SP) running in Docker. The testbed is provisioned
via `sso_testbed.py --json-output` and torn down after the session.

Prerequisites:
    - Docker services running (make up)
    - Playwright browsers installed (poetry run playwright install chromium)
"""

import json
import subprocess
import sys

import pytest
from helpers.maildev import clear_emails, is_available

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IDP_SUBDOMAIN = "e2e-idp"
SP_SUBDOMAIN = "e2e-sp"
DOCKER_COMPOSE = ["docker", "compose"]


def _flush_memcached():
    """Flush memcached to clear rate limit counters."""
    subprocess.run(
        [
            *DOCKER_COMPOSE,
            "exec",
            "-T",
            "memcached",
            "sh",
            "-c",
            'echo "flush_all" | nc localhost 11211',
        ],
        capture_output=True,
        timeout=10,
    )


# ---------------------------------------------------------------------------
# Session-scoped testbed fixture
# ---------------------------------------------------------------------------


def _run_testbed(*extra_args: str) -> str:
    """Run sso_testbed.py inside the app container and return stdout."""
    cmd = [
        *DOCKER_COMPOSE,
        "exec",
        "-T",
        "app",
        "python",
        "./dev/sso_testbed.py",
        "--idp-subdomain",
        IDP_SUBDOMAIN,
        "--sp-subdomain",
        SP_SUBDOMAIN,
        *extra_args,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"sso_testbed.py failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
    return result.stdout


@pytest.fixture(scope="session")
def e2e_config():
    """Provision two tenants wired for cross-tenant SAML SSO.

    Yields the JSON config dict with idp/sp connection details.
    Tears down test tenants after the session.
    """
    _flush_memcached()
    stdout = _run_testbed("--json-output")
    config = json.loads(stdout)

    yield config

    # Teardown: delete test tenants
    try:
        _run_testbed("--teardown")
    except Exception as exc:
        print(f"Warning: testbed teardown failed: {exc}", file=sys.stderr)


@pytest.fixture(scope="session")
def idp_config(e2e_config):
    """Shorthand for the IdP portion of e2e_config."""
    return e2e_config["idp"]


@pytest.fixture(scope="session")
def sp_config(e2e_config):
    """Shorthand for the SP portion of e2e_config."""
    return e2e_config["sp"]


# ---------------------------------------------------------------------------
# Browser configuration
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Override default browser context settings for E2E tests."""
    return {
        **browser_context_args,
        "ignore_https_errors": True,
        "viewport": {"width": 1280, "height": 720},
    }


# ---------------------------------------------------------------------------
# Login helper
# ---------------------------------------------------------------------------


@pytest.fixture()
def login(page):
    """Return a function that logs a user in via the dev-only instant login endpoint.

    Usage:
        login(base_url, email, password)

    Uses GET /dev/login?email=... to set a session cookie and redirect
    to /dashboard. The full multi-step login flow is tested separately
    in test_login.py.
    """

    def _login(base_url: str, email: str):
        page.goto(f"{base_url}/dev/login?email={email}")
        page.wait_for_url("**/dashboard**", timeout=5000)

    return _login


# ---------------------------------------------------------------------------
# MailDev utilities
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_test_state():
    """Clear MailDev inbox and rate limits before each test."""
    clear_emails()
    _flush_memcached()


# ---------------------------------------------------------------------------
# Skip checks
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items):
    """Skip all E2E tests if MailDev is not reachable."""
    if not is_available():
        skip = pytest.mark.skip(reason="MailDev not available (is Docker running?)")
        for item in items:
            item.add_marker(skip)
