"""E2E tests for OIDC provider flows beyond the authorization-code happy path.

Each flow runs in a real browser against the dev stack:

  1. Device authorization grant (RFC 8628): a public device client starts the
     flow, the browser opens ``verification_uri_complete`` anonymously, signs
     in, comes back to /device with the code prefilled, approves, and the
     device's poll at the token endpoint returns tokens.
  2. Remembered consent across two separate sign-ins: the consent page shows
     on the first authorization only.
  3. ``response_mode=form_post`` under the real CSP: the auto-submitting page
     actually submits (its nonce'd script runs and ``form-action`` admits the
     RP origin), and the RP receives ``code`` and ``state`` as a form POST.

Builds on the ``oidc_config`` testbed tenant. Every test gets its own client
(created here, inside the app container) so remembered consent left behind by
other tests cannot change what the browser sees.
"""

import json
import subprocess
import time
import uuid
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from tests.e2e.conftest import DOCKER_COMPOSE, enter_email_and_reach_password_form

# The dev reverse proxy serves tenants with a self-signed certificate.
_VERIFY = False

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

# A relying party on another origin. Nothing serves it: the browser's POST is
# intercepted with a Playwright route. Being off-origin is the point, the CSP
# ``form-action`` must be widened to it for the auto-submit to go through.
FORM_POST_RP_ORIGIN = "https://rp.form-post-e2e.example.com"
FORM_POST_REDIRECT_URI = f"{FORM_POST_RP_ORIGIN}/callback"

# Runs inside the app container (cwd /app, so app modules import). Creates one
# OIDC-enabled, available-to-all client per spec and prints their details.
_CREATE_CLIENTS = """
import json, sys
import database, database.oauth2
from services.users import get_user_id_by_email

args = json.loads(sys.argv[1])
tid = args["tenant_id"]
uid = str(get_user_id_by_email(tid, args["user_email"]))
out = {}
for spec in args["clients"]:
    for existing in database.oauth2.get_all_clients(tid, client_type="normal"):
        if existing["name"] == spec["name"]:
            database.oauth2.delete_client(tid, existing["client_id"])
    client = database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=tid,
        name=spec["name"],
        redirect_uris=spec["redirect_uris"],
        created_by=uid,
        device_grant_enabled=spec.get("device_grant_enabled", False),
        is_public=spec.get("is_public", False),
    )
    database.oauth2.update_client_oidc_settings(
        tid, client["client_id"], oidc_enabled=True, available_to_all=True
    )
    out[spec["key"]] = {
        "id": str(client["id"]),
        "client_id": client["client_id"],
        "client_secret": client.get("client_secret"),
    }
print(json.dumps(out))
"""


def _run_sql(sql: str) -> str:
    result = subprocess.run(
        [*DOCKER_COMPOSE, "exec", "-T", "db", "psql", "-U", "postgres", "-d", "appdb", "-At"]
        + ["-c", sql],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"SQL failed (rc={result.returncode}): {result.stderr}\nSQL: {sql}")
    return result.stdout.strip()


def _create_clients(cfg: dict, clients: list[dict]) -> dict:
    payload = json.dumps(
        {"tenant_id": cfg["tenant_id"], "user_email": cfg["user_email"], "clients": clients}
    )
    result = subprocess.run(
        [*DOCKER_COMPOSE, "exec", "-T", "app", "python", "-c", _CREATE_CLIENTS, payload],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"client setup failed:\n{result.stdout}\n{result.stderr}")
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def flow_clients(oidc_config):
    """Per-module clients on the OIDC testbed tenant (deleted with the tenant)."""
    return _create_clients(
        oidc_config,
        [
            {
                "key": "device",
                "name": "OIDC E2E Device",
                "redirect_uris": [oidc_config["redirect_uri"]],
                "device_grant_enabled": True,
                "is_public": True,
            },
            {
                "key": "consent",
                "name": "OIDC E2E Consent",
                "redirect_uris": [oidc_config["redirect_uri"]],
            },
            {
                "key": "form_post",
                "name": "OIDC E2E Form Post",
                "redirect_uris": [FORM_POST_REDIRECT_URI],
            },
        ],
    )


def _real_login(page, cfg: dict) -> None:
    """Email, password and MFA (BYPASS_OTP accepts any six digits)."""
    enter_email_and_reach_password_form(page, cfg["base_url"], cfg["user_email"], cfg["password"])
    page.wait_for_url("**/mfa/verify**", timeout=10000)
    page.locator("#code").fill("123456")
    page.locator("#mfaVerifyForm button[type='submit']").click()


def _verify_id_token(client: httpx.Client, base_url: str, id_token: str, audience: str) -> dict:
    jwks = client.get(f"{base_url}/.well-known/jwks.json").json()
    kid = jwt.get_unverified_header(id_token)["kid"]
    entry = next(k for k in jwks["keys"] if k["kid"] == kid)
    return jwt.decode(
        id_token,
        RSAAlgorithm.from_jwk(json.dumps(entry)),
        algorithms=["RS256"],
        audience=audience,
        issuer=base_url,
    )


# ---------------------------------------------------------------------------
# 1. Device authorization grant
# ---------------------------------------------------------------------------


class TestDeviceAuthorizationGrant:
    def test_device_signs_in_after_browser_approval(self, page, oidc_config, flow_clients):
        cfg = oidc_config
        base_url = cfg["base_url"]
        device = flow_clients["device"]

        with httpx.Client(verify=_VERIFY, timeout=15.0) as client:
            # --- The device starts the flow (public client: client_id only).
            start = client.post(
                f"{base_url}/oauth2/device_authorization",
                data={"client_id": device["client_id"], "scope": "openid profile email"},
            )
            assert start.status_code == 200, start.text
            started = start.json()
            assert started["verification_uri"] == f"{base_url}/device"
            user_code = started["user_code"]
            interval = int(started["interval"])

            def poll() -> httpx.Response:
                return client.post(
                    f"{base_url}/oauth2/token",
                    data={
                        "grant_type": DEVICE_CODE_GRANT,
                        "client_id": device["client_id"],
                        "device_code": started["device_code"],
                    },
                )

            # Nobody has approved yet.
            pending = poll()
            assert pending.status_code == 400
            assert pending.json()["error"] == "authorization_pending"

            # --- The person opens the link on another screen, signed out.
            page.goto(started["verification_uri_complete"])
            page.wait_for_url(f"{base_url}/login**", timeout=10000)
            _real_login(page, cfg)

            # Back on /device with the code stashed and prefilled: no re-entry.
            page.wait_for_url(f"{base_url}/device**", timeout=15000)
            page.wait_for_selector("#user_code", timeout=10000)
            assert page.locator("#user_code").input_value() == user_code
            page.locator("form[action='/device'] button[type='submit']").click()

            # The confirmation page names the app; approve.
            page.wait_for_selector("button[name='action'][value='allow']", timeout=10000)
            assert "OIDC E2E Device" in page.content()
            page.locator("button[name='action'][value='allow']").click()
            page.wait_for_selector("#device-outcome[data-outcome='approved']", timeout=10000)

            # --- The device's next poll (after the interval) gets the tokens.
            time.sleep(interval + 1)
            done = poll()
            assert done.status_code == 200, done.text
            tokens = done.json()
            assert tokens["token_type"].lower() == "bearer"
            assert tokens["access_token"]

            claims = _verify_id_token(client, base_url, tokens["id_token"], device["client_id"])
            assert claims["sub"] and claims["sub"] != cfg["user_email"]
            # Device tokens are not tied to the approving browser session.
            assert "sid" not in claims

            userinfo = client.get(
                f"{base_url}/userinfo",
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            assert userinfo.status_code == 200, userinfo.text
            assert userinfo.json()["email"] == cfg["user_email"]

            # The device code is single-use.
            again = poll()
            assert again.status_code == 400
            assert again.json()["error"] == "invalid_grant"


# ---------------------------------------------------------------------------
# 2. Remembered consent across two sign-ins
# ---------------------------------------------------------------------------


def _authorize_url(cfg: dict, client_id: str, redirect_uri: str, **extra: str) -> str:
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
            "state": extra.pop("state", "e2e-flows-state"),
            "nonce": "e2e-flows-nonce",
            **extra,
        }
    )
    return f"{cfg['base_url']}/oauth2/authorize?{query}"


class TestRememberedConsentAcrossSignIns:
    def test_second_sign_in_skips_the_consent_page(self, page, oidc_config, flow_clients):
        cfg = oidc_config
        base_url = cfg["base_url"]
        app = flow_clients["consent"]
        authorize = _authorize_url(cfg, app["client_id"], cfg["redirect_uri"])

        # Pages the browser actually rendered (redirects never commit).
        rendered: list[str] = []
        page.on("framenavigated", lambda f: f.parent_frame is None and rendered.append(f.url))

        # --- First sign-in: login, then the consent page, then the RP.
        page.goto(authorize)
        page.wait_for_url(f"{base_url}/login**", timeout=10000)
        _real_login(page, cfg)
        page.wait_for_selector("button[name='action'][value='allow']", timeout=15000)
        assert "/oauth2/authorize" in page.url
        page.locator("button[name='action'][value='allow']").click()
        page.wait_for_url(f"{cfg['redirect_uri']}?*", timeout=10000)
        first_code = parse_qs(urlparse(page.url).query)["code"][0]

        # --- Sign out of WeftID entirely.
        page.goto(f"{base_url}/dashboard")
        page.locator("form[action='/logout']").first.evaluate("form => form.submit()")
        page.wait_for_url(f"{base_url}/login**", timeout=10000)
        page.goto(f"{base_url}/dashboard")
        page.wait_for_url(f"{base_url}/login**", timeout=10000)

        # --- Second sign-in: login, then straight to the RP with a new code.
        rendered.clear()
        page.goto(authorize)
        page.wait_for_url(f"{base_url}/login**", timeout=10000)
        _real_login(page, cfg)
        page.wait_for_url(f"{cfg['redirect_uri']}?*", timeout=15000)
        params = parse_qs(urlparse(page.url).query)
        assert params["state"] == ["e2e-flows-state"]
        assert params["code"][0] and params["code"][0] != first_code
        assert not [u for u in rendered if "/oauth2/authorize" in u], rendered

        # One grant, granted once.
        assert (
            _run_sql(f"SELECT count(*) FROM oauth2_consent_grants WHERE client_id = '{app['id']}';")
            == "1"
        )


# ---------------------------------------------------------------------------
# 3. response_mode=form_post under the real CSP
# ---------------------------------------------------------------------------


class TestFormPostResponseMode:
    def test_form_post_auto_submits_to_the_rp(self, page, login, oidc_config, flow_clients):
        cfg = oidc_config
        base_url = cfg["base_url"]
        app = flow_clients["form_post"]
        state = f"fp-{uuid.uuid4().hex[:12]}"

        csp_errors: list[str] = []
        page.on(
            "console",
            lambda m: (
                m.type == "error"
                and "Content Security Policy" in m.text
                and csp_errors.append(m.text)
            ),
        )

        rp_posts: list[dict] = []

        def _rp_callback(route):
            req = route.request
            rp_posts.append(
                {
                    "method": req.method,
                    "content_type": req.headers.get("content-type", ""),
                    "form": parse_qs(req.post_data or ""),
                    "query": urlparse(req.url).query,
                }
            )
            route.fulfill(status=200, content_type="text/html", body="<p>RP received</p>")

        page.route(f"{FORM_POST_REDIRECT_URI}*", _rp_callback)

        login(base_url, cfg["user_email"])
        authorize = _authorize_url(
            cfg, app["client_id"], FORM_POST_REDIRECT_URI, response_mode="form_post", state=state
        )
        page.goto(authorize)
        # Fresh client: the consent page shows first. Allowing renders the
        # auto-submitting form page, whose script must post it to the RP.
        page.wait_for_selector("button[name='action'][value='allow']", timeout=10000)
        page.locator("button[name='action'][value='allow']").click()
        page.wait_for_url(FORM_POST_REDIRECT_URI, timeout=10000)
        assert "RP received" in page.content()

        (post,) = rp_posts
        assert post["method"] == "POST"
        assert post["content_type"].startswith("application/x-www-form-urlencoded")
        assert post["query"] == ""  # the code never rides in the URL
        assert post["form"]["state"] == [state]
        code = post["form"]["code"][0]
        assert code
        assert csp_errors == []

        # The posted code is a real one: the RP backend can redeem it.
        with httpx.Client(verify=_VERIFY, timeout=15.0) as client:
            resp = client.post(
                f"{base_url}/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": app["client_id"],
                    "client_secret": app["client_secret"],
                    "code": code,
                    "redirect_uri": FORM_POST_REDIRECT_URI,
                },
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["id_token"]
