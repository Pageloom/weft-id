"""Upstream OIDC login E2E (WeftID as its own upstream IdP, in a real browser).

Drives the one upstream-OIDC flow unit tests cannot cover: real redirects,
real session cookies on two hosts, and the callback handled end to end.

Topology (provisioned by `dev/oidc_loopback_testbed.py`, run inside the app
container): a provider tenant (`e2e-oidc-op`) exposes WeftID's downstream
OpenID Provider; a relying-party tenant (`e2e-oidc-rp`) holds a generic
upstream OIDC connection pointed at it (default + JIT). The RP's outbound
hops (discovery, JWKS, token, userinfo) reach the OP through the SSRF
guard's dev-only base-domain rewrite.

The browser flow per sign-in:

  1. establish an OP session (dev instant login on the OP host)
  2. RP /login -> enter the email -> auth routing sends the browser to
     /auth/oidc/{connection}/login -> off-origin hop to the OP's
     /oauth2/authorize
  3. approve the consent page on the OP
  4. callback on the RP: state check, code exchange (PKCE + client_secret_basic),
     ID-token validation against the OP's JWKS, userinfo merge, correlation
  5. land on the RP dashboard

Test ordering is load-bearing: the first sign-in JIT-provisions the RP user
and the `(connection, sub)` link; the second sign-in must correlate on that
link (no duplicate user, no second link). Pytest preserves definition order
within a module, and E2E runs sequentially (`-n 0`).

All assertions are SQL via `psql`, matching `test_scim_loopback_e2e.py`.
"""

import json
import subprocess

import pytest

from tests.e2e.conftest import DOCKER_COMPOSE

_TESTBED = "./dev/oidc_loopback_testbed.py"


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run_sql(sql: str) -> str:
    """Execute one SQL statement against the dev DB; return trimmed stdout."""
    result = subprocess.run(
        [
            *DOCKER_COMPOSE,
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "postgres",
            "-d",
            "appdb",
            "-At",
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SQL failed (rc={result.returncode}): {result.stderr}\nSQL: {sql}")
    return result.stdout.strip()


def _run_testbed(*extra_args: str, timeout: int = 90) -> str:
    cmd = [*DOCKER_COMPOSE, "exec", "-T", "app", "python", _TESTBED, *extra_args]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"loopback testbed failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# SQL lookups
# ---------------------------------------------------------------------------


def _rp_user_ids(rp_tenant_id: str, email: str) -> list[str]:
    raw = _run_sql(
        "SELECT u.id FROM users u JOIN user_emails ue ON ue.user_id = u.id "
        f"WHERE u.tenant_id = '{rp_tenant_id}' AND ue.email = '{email}' ORDER BY u.id;"
    )
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _links(connection_id: str) -> list[tuple[str, str]]:
    """All (user_id, sub) link rows for the connection."""
    raw = _run_sql(
        "SELECT user_id || '|' || sub FROM oidc_idp_user_links "
        f"WHERE idp_id = '{connection_id}' ORDER BY created_at;"
    )
    rows = []
    for line in raw.splitlines():
        if line.strip():
            user_id, sub = line.strip().split("|", 1)
            rows.append((user_id, sub))
    return rows


def _event_count(tenant_id: str, event_type: str) -> int:
    return int(
        _run_sql(
            "SELECT count(*) FROM event_logs "
            f"WHERE tenant_id = '{tenant_id}' AND event_type = '{event_type}';"
        )
    )


def _op_user_id(op_tenant_id: str, email: str) -> str:
    return _run_sql(
        "SELECT u.id FROM users u JOIN user_emails ue ON ue.user_id = u.id "
        f"WHERE u.tenant_id = '{op_tenant_id}' AND ue.email = '{email}';"
    )


# ---------------------------------------------------------------------------
# Browser flow
# ---------------------------------------------------------------------------


def _sign_in_via_upstream_oidc(page, login, cfg: dict) -> None:
    """Drive one full upstream-OIDC sign-in and land on the RP dashboard."""
    op = cfg["op"]
    rp = cfg["rp"]

    # 1. OP session on the provider host (separate cookie jar from the RP host).
    login(op["base_url"], op["user_email"])

    # 2. RP login: the email step routes to the default JIT OIDC connection
    #    (first time) or to the linked connection (later sign-ins). Either way
    #    the browser ends up on the OP's consent page.
    page.goto(f"{rp['base_url']}/login")
    page.locator("#email").fill(op["user_email"])
    page.locator("#emailForm button[type='submit']").click()

    # 3. Consent on the OP. The URL proves the hop went through the RP's
    #    /auth/oidc/{id}/login (state/nonce/PKCE were minted on the RP host).
    page.wait_for_url(f"{op['base_url']}/oauth2/authorize?*", timeout=15000)
    page.wait_for_selector("button[name='action'][value='allow']", timeout=10000)
    page.locator("button[name='action'][value='allow']").click()

    # 4 + 5. Callback on the RP, then the dashboard.
    page.wait_for_url(f"{rp['base_url']}/dashboard**", timeout=20000)
    assert "error=" not in page.url, f"Login landed with an error: {page.url}"


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def loopback_config():
    """Provision the closed-loop OIDC test bed; yield its JSON config.

    Tears down before (clearing stale data from an interrupted run) and
    after the module. Module-scoped so the second-sign-in test observes the
    link the first one created.
    """
    try:
        _run_testbed("--teardown")
    except Exception:
        pass

    config = json.loads(_run_testbed("--json-output"))
    yield config

    try:
        _run_testbed("--teardown")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# First sign-in: JIT provisioning
# ---------------------------------------------------------------------------


class TestUpstreamOidcFirstSignIn:
    """First sign-in JIT-creates the RP user and the (connection, sub) link."""

    def test_first_sign_in_provisions_user_and_link(self, page, login, loopback_config):
        cfg = loopback_config
        op, rp = cfg["op"], cfg["rp"]
        email = op["user_email"]

        # Precondition: the RP has no such user and no link yet.
        assert _rp_user_ids(rp["tenant_id"], email) == []
        assert _links(rp["connection_id"]) == []

        _sign_in_via_upstream_oidc(page, login, cfg)

        # Exactly one RP user was created, with the OP's profile claims mapped.
        user_ids = _rp_user_ids(rp["tenant_id"], email)
        assert len(user_ids) == 1, f"Expected one JIT user; got {user_ids}"
        rp_user_id = user_ids[0]

        names = _run_sql(
            f"SELECT first_name || '|' || last_name FROM users WHERE id = '{rp_user_id}';"
        )
        assert names == f"{op['user_first_name']}|{op['user_last_name']}"

        # OIDC-only account: no password, verified primary email.
        no_password = _run_sql(
            f"SELECT password_hash IS NULL FROM users WHERE id = '{rp_user_id}';"
        )
        assert no_password == "t"
        verified = _run_sql(
            "SELECT verified_at IS NOT NULL FROM user_emails "
            f"WHERE user_id = '{rp_user_id}' AND is_primary = true;"
        )
        assert verified == "t"

        # One link, bound to the OP's stable subject (its user id, never the email).
        links = _links(rp["connection_id"])
        assert len(links) == 1, f"Expected one link row; got {links}"
        link_user_id, sub = links[0]
        assert link_user_id == rp_user_id
        assert sub == _op_user_id(op["tenant_id"], email)
        assert sub != email

        # Audit trail on the RP side. A JIT sign-in is recorded by the
        # provisioning event alone (mirroring SAML's user_created_jit), so no
        # oidc_login_completed is expected yet.
        assert _event_count(rp["tenant_id"], "oidc_user_jit_provisioned") == 1
        assert _event_count(rp["tenant_id"], "oidc_login_started") == 1
        assert _event_count(rp["tenant_id"], "oidc_login_completed") == 0
        assert _event_count(rp["tenant_id"], "oidc_login_failed") == 0


# ---------------------------------------------------------------------------
# Second sign-in: correlation on sub
# ---------------------------------------------------------------------------


class TestUpstreamOidcSecondSignIn:
    """A second sign-in correlates on the existing link: no duplicate."""

    def test_second_sign_in_correlates_on_sub(self, page, login, loopback_config):
        cfg = loopback_config
        op, rp = cfg["op"], cfg["rp"]
        email = op["user_email"]

        # Precondition: the first test ran and left exactly one user + link.
        before_users = _rp_user_ids(rp["tenant_id"], email)
        before_links = _links(rp["connection_id"])
        assert len(before_users) == 1
        assert len(before_links) == 1

        # Fresh browser context (function-scoped `page`): both sessions are gone,
        # so this is a cold second sign-in, not a session resume.
        _sign_in_via_upstream_oidc(page, login, cfg)

        # Same single user, same single link, same subject.
        assert _rp_user_ids(rp["tenant_id"], email) == before_users
        assert _links(rp["connection_id"]) == before_links

        # No second JIT event; this login completed as a sign-in of the
        # linked user (the first, JIT, sign-in logged no completed event).
        assert _event_count(rp["tenant_id"], "oidc_user_jit_provisioned") == 1
        assert _event_count(rp["tenant_id"], "oidc_login_started") == 2
        assert _event_count(rp["tenant_id"], "oidc_login_completed") == 1
        assert _event_count(rp["tenant_id"], "oidc_login_failed") == 0

        # The RP session belongs to the linked user: the profile form is
        # pre-filled with the name the OP asserted.
        page.goto(f"{rp['base_url']}/account/profile")
        page.wait_for_selector("#first_name", timeout=10000)
        assert page.locator("#first_name").input_value() == op["user_first_name"]
        assert page.locator("#last_name").input_value() == op["user_last_name"]
