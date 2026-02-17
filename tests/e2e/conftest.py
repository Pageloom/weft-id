"""E2E test fixtures for SAML SSO flows.

Uses Playwright to drive a real browser against WeftId tenants
running in Docker. Two testbed configurations are available:

  - Two-tenant (sso_testbed.py): IdP + SP for basic SSO flows
  - Three-tenant chain (sso_chain_testbed.py): upstream IdP → mid → leaf SP
  - Extras (sso_extras_testbed.py): domain binding + group hierarchy data

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
# Generic runner
# ---------------------------------------------------------------------------


def _run_script(script: str, *extra_args: str, timeout: int = 60) -> str:
    """Run a Python script inside the app container and return stdout."""
    cmd = [
        *DOCKER_COMPOSE,
        "exec",
        "-T",
        "app",
        "python",
        script,
        *extra_args,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{script} failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
    return result.stdout


def _run_testbed(*extra_args: str) -> str:
    """Run sso_testbed.py inside the app container."""
    return _run_script(
        "./dev/sso_testbed.py",
        "--idp-subdomain",
        IDP_SUBDOMAIN,
        "--sp-subdomain",
        SP_SUBDOMAIN,
        *extra_args,
    )


# ---------------------------------------------------------------------------
# Session-scoped testbed fixture (two-tenant)
# ---------------------------------------------------------------------------


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
# Session-scoped extras fixture (domain binding + group hierarchy)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def extras_config(e2e_config):
    """Add domain binding and group hierarchy test data to the two-tenant setup.

    Depends on e2e_config to ensure the base testbed is provisioned first.
    """
    stdout = _run_script(
        "./dev/sso_extras_testbed.py",
        "--json-output",
        "--idp-subdomain",
        IDP_SUBDOMAIN,
        "--sp-subdomain",
        SP_SUBDOMAIN,
    )
    return json.loads(stdout)


# ---------------------------------------------------------------------------
# Session-scoped chain fixture (three-tenant)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def chain_config():
    """Provision three tenants wired in a chain for passthrough SSO testing.

    upstream (IdP) → mid (IdP/SP) → leaf (SP)

    Yields the JSON config dict. Tears down after session.
    """
    _flush_memcached()
    stdout = _run_script(
        "./dev/sso_chain_testbed.py",
        "--json-output",
        timeout=90,
    )
    config = json.loads(stdout)
    import pprint

    pprint.pp(config)
    yield config

    try:
        _run_script("./dev/sso_chain_testbed.py", "--teardown")
    except Exception as exc:
        print(f"Warning: chain testbed teardown failed: {exc}", file=sys.stderr)


@pytest.fixture(scope="session")
def upstream_config(chain_config):
    """Shorthand for the upstream IdP portion of chain_config."""
    return chain_config["upstream"]


@pytest.fixture(scope="session")
def mid_config(chain_config):
    """Shorthand for the mid IdP/SP portion of chain_config."""
    return chain_config["mid"]


@pytest.fixture(scope="session")
def leaf_config(chain_config):
    """Shorthand for the leaf SP portion of chain_config."""
    return chain_config["leaf"]


@pytest.fixture(scope="session")
def chain_user(chain_config):
    """Shorthand for the chain test user credentials."""
    return chain_config["chain_user"]


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
        login(base_url, email)

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
