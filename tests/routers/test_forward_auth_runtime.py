"""Route/integration tests for the forward-auth runtime handshake.

Exercises the four endpoints end to end against the real DB schema:

  * /check    -- allow (cookie), deny (no app), start redirect (no cookie),
                 public-path bypass, expired/tampered cookie, rate-limit trip,
                 forwarded-header contents.
  * /start    -- redirect to the canonical tenant host /authorize.
  * /authorize -- not-signed-in bounce, allow (mint token), deny (no grant),
                 open-redirect rejection, cross-tenant domain rejection.
  * /callback -- happy path (sets cookie), single-use replay, cross-domain
                 token substitution, open-redirect rejection.

Per-test-tenant unique domain/portal/app names avoid colliding with the
globally-unique ``portal_host`` constraint under parallel test workers.
"""

from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import database
import pytest
import settings
from utils.forward_auth import (
    FORWARD_AUTH_COOKIE_NAME,
    build_forward_auth_cookie_value,
    mint_authorization_token,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def names(test_tenant):
    """Unique domain / portal / app host derived from the tenant id."""
    suffix = str(test_tenant["id"]).replace("-", "")[:12]
    domain = f"fa-{suffix}.example"
    return {
        "domain": domain,
        "portal_host": f"auth.{domain}",
        "app_host": f"app.{domain}",
        "app_url": f"https://app.{domain}",
    }


@pytest.fixture
def verified_domain(test_tenant, names):
    """A verified, enabled protected domain owned by test_tenant."""
    return database.protected_domains.create_protected_domain(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        domain=names["domain"],
        portal_host=names["portal_host"],
        created_by=None,
        verification_status="verified",
    )


@pytest.fixture
def proxy_app(test_tenant, names, verified_domain):
    """An enabled proxy app fronting the app host, emitting all forwarded headers."""
    return database.proxy_apps.create_proxy_app(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        protected_domain_id=str(verified_domain["id"]),
        name="Runtime App",
        external_url=names["app_url"],
        created_by=None,
        public_paths=["/health", "/static/*"],
        header_config={"user": True, "email": True, "groups": True, "display_name": True},
        available_to_all=False,
        enabled=True,
    )


@pytest.fixture
def granted_user(test_tenant, test_user, proxy_app):
    """test_user in a group that is granted access to proxy_app."""
    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Runtime Group",
        description=None,
        group_type="weftid",
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(group["id"]), str(test_user["id"])
    )
    database.sp_group_assignments.create_proxy_app_assignment(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        proxy_app_id=str(proxy_app["id"]),
        group_id=str(group["id"]),
        assigned_by=str(test_user["id"]),
    )
    return test_user


def _cookie_for(user_id="u1", email="a@b.com", name="Alice", groups=None):
    return build_forward_auth_cookie_value(
        user_id=user_id, email=email, display_name=name, groups=groups or ["eng"]
    )


def _tenant_host(test_tenant):
    return f"{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"


def _session(user_id):
    mock_session = {"user_id": str(user_id)}
    return patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: mock_session),
    )


# ---------------------------------------------------------------------------
# /check
# ---------------------------------------------------------------------------


class TestCheck:
    def test_no_cookie_redirects_to_start(self, client, names, proxy_app):
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["app_host"],
                "x-forwarded-uri": "/dash",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        loc = resp.headers["location"]
        assert loc.startswith("/forward-auth/start")
        assert "rd=%2Fdash" in loc

    def test_valid_cookie_allows_with_headers(self, client, names, proxy_app):
        cookie = _cookie_for(user_id="u-9", email="x@y.com", name="X Y", groups=["g1", "g2"])
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["app_host"],
                "x-forwarded-uri": "/dash",
            },
            cookies={FORWARD_AUTH_COOKIE_NAME: cookie},
            follow_redirects=False,
        )
        assert resp.status_code == 200
        assert resp.headers["X-Forwarded-User"] == "u-9"
        assert resp.headers["X-Forwarded-Email"] == "x@y.com"
        assert resp.headers["X-Forwarded-Display-Name"] == "X Y"
        assert resp.headers["X-Forwarded-Groups"] == "g1,g2"

    def test_public_path_bypass_no_session(self, client, names, proxy_app):
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["app_host"],
                "x-forwarded-uri": "/health",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 200
        assert "X-Forwarded-User" not in resp.headers

    def test_public_wildcard_bypass(self, client, names, proxy_app):
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["app_host"],
                "x-forwarded-uri": "/static/app.css",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 200

    def test_public_path_traversal_not_bypassed(self, client, names, proxy_app):
        # '/static/*' is public, but '/static/../dash' must NOT bypass auth: a
        # backend normalizing '..' would resolve it to a protected path. With no
        # cookie the gate must redirect to /start, not return 200.
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["app_host"],
                "x-forwarded-uri": "/static/../dash",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("/forward-auth/start")

    def test_unknown_app_fails_closed_403(self, client, names, verified_domain):
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": f"nope.{names['domain']}",
                "x-forwarded-uri": "/",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_tampered_cookie_redirects_and_logs_expiry(self, client, names, proxy_app):
        good = _cookie_for()
        tampered = good[:-3] + "AAA"
        with patch("services.forward_auth.log_event") as log:
            resp = client.get(
                "/forward-auth/check",
                headers={
                    "host": names["portal_host"],
                    "x-forwarded-host": names["app_host"],
                    "x-forwarded-uri": "/dash",
                },
                cookies={FORWARD_AUTH_COOKIE_NAME: tampered},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        assert any(
            c.kwargs.get("event_type") == "proxy_session_expired" for c in log.call_args_list
        )

    def test_expired_cookie_redirects_to_start(self, client, names, proxy_app):
        expired = build_forward_auth_cookie_value(
            user_id="u1", email="a@b.com", display_name="A", groups=[], ttl_seconds=-10
        )
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["app_host"],
                "x-forwarded-uri": "/dash",
            },
            cookies={FORWARD_AUTH_COOKIE_NAME: expired},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("/forward-auth/start")

    def test_sole_app_fallback_when_host_is_portal(self, client, names, proxy_app):
        cookie = _cookie_for()
        resp = client.get(
            "/forward-auth/check",
            headers={
                "host": names["portal_host"],
                "x-forwarded-host": names["portal_host"],
                "x-forwarded-uri": "/dash",
            },
            cookies={FORWARD_AUTH_COOKIE_NAME: cookie},
            follow_redirects=False,
        )
        assert resp.status_code == 200

    def test_rate_limit_trips(self, client, names, proxy_app):
        # The test env has no memcached (ratelimit fails open), so assert the
        # endpoint's RateLimitError -> 429 translation directly by forcing the
        # limiter to raise.
        from services.exceptions import RateLimitError

        with patch(
            "routers.forward_auth.runtime.ratelimit.prevent",
            side_effect=RateLimitError(message="too many"),
        ):
            resp = client.get(
                "/forward-auth/check",
                headers={
                    "host": names["portal_host"],
                    "x-forwarded-host": names["app_host"],
                    "x-forwarded-uri": "/health",
                },
                follow_redirects=False,
            )
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------


class TestStart:
    def test_redirects_to_canonical_authorize(self, client, names, verified_domain, test_tenant):
        resp = client.get(
            "/forward-auth/start",
            params={"rd": "/dashboard"},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        parsed = urlsplit(resp.headers["location"])
        assert parsed.netloc == _tenant_host(test_tenant)
        assert parsed.path == "/forward-auth/authorize"
        q = parse_qs(parsed.query)
        assert q["domain"] == [names["domain"]]
        assert q["portal_host"] == [names["portal_host"]]
        assert q["rd"] == ["/dashboard"]


# ---------------------------------------------------------------------------
# /authorize  (canonical tenant host)
# ---------------------------------------------------------------------------


class TestAuthorize:
    def test_not_signed_in_bounces_to_login(self, client, names, verified_domain, test_tenant):
        resp = client.get(
            "/forward-auth/authorize",
            params={"domain": names["domain"], "portal_host": names["portal_host"], "rd": "/dash"},
            headers={"host": _tenant_host(test_tenant)},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    def test_cross_tenant_domain_rejected(self, client, test_tenant):
        resp = client.get(
            "/forward-auth/authorize",
            params={"domain": "someone-else.example", "portal_host": "auth.someone-else.example"},
            headers={"host": _tenant_host(test_tenant)},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_signed_in_granted_mints_token(self, client, names, granted_user, test_tenant):
        with _session(granted_user["id"]):
            resp = client.get(
                "/forward-auth/authorize",
                params={
                    "domain": names["domain"],
                    "portal_host": names["portal_host"],
                    "rd": f"{names['app_url']}/dash",
                },
                headers={"host": _tenant_host(test_tenant)},
                follow_redirects=False,
            )
        assert resp.status_code == 302
        loc = resp.headers["location"]
        assert loc.startswith(f"https://{names['portal_host']}/forward-auth/callback?token=")

    def test_signed_in_denied_returns_403(self, client, names, test_user, proxy_app, test_tenant):
        with _session(test_user["id"]):
            resp = client.get(
                "/forward-auth/authorize",
                params={
                    "domain": names["domain"],
                    "portal_host": names["portal_host"],
                    "rd": f"{names['app_url']}/dash",
                },
                headers={"host": _tenant_host(test_tenant)},
                follow_redirects=False,
            )
        assert resp.status_code == 403

    def test_open_redirect_rd_rejected(self, client, names, granted_user, test_tenant):
        with _session(granted_user["id"]):
            resp = client.get(
                "/forward-auth/authorize",
                params={
                    "domain": names["domain"],
                    "portal_host": names["portal_host"],
                    "rd": "https://evil.example/phish",
                },
                headers={"host": _tenant_host(test_tenant)},
                follow_redirects=False,
            )
        assert resp.status_code == 403

    def test_portal_host_mismatch_rejected(self, client, names, granted_user, test_tenant):
        # A forged portal_host that is not the registered one must be rejected so
        # the minted token cannot be redirected to an attacker host.
        with _session(granted_user["id"]):
            resp = client.get(
                "/forward-auth/authorize",
                params={
                    "domain": names["domain"],
                    "portal_host": "evil.attacker.example",
                    "rd": f"{names['app_url']}/dash",
                },
                headers={"host": _tenant_host(test_tenant)},
                follow_redirects=False,
            )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# /callback  (portal host)
# ---------------------------------------------------------------------------


class TestCallback:
    def _issue(self, tenant_id, user_id, app_id, rd, domain):
        from services import forward_auth as fa_service

        return fa_service.issue_authorization_token(
            user_id=str(user_id),
            tenant_id=str(tenant_id),
            domain=domain,
            app_id=str(app_id),
            rd=rd,
        )

    def test_happy_path_sets_cookie_and_redirects(
        self, client, names, granted_user, proxy_app, test_tenant
    ):
        token = self._issue(
            test_tenant["id"],
            granted_user["id"],
            proxy_app["id"],
            f"{names['app_url']}/dash",
            names["domain"],
        )
        resp = client.get(
            "/forward-auth/callback",
            params={"token": token},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert resp.headers["location"] == f"{names['app_url']}/dash"
        set_cookie = resp.headers.get("set-cookie", "")
        assert FORWARD_AUTH_COOKIE_NAME in set_cookie
        assert f"Domain={names['domain']}" in set_cookie

    def test_user_inactivated_after_mint_denied(
        self, client, names, granted_user, proxy_app, test_tenant
    ):
        # Identity freshness: a token minted while the user was active must NOT
        # yield a cookie if the user is inactivated before the callback runs.
        # /callback rebuilds identity from the live user record and fails closed.
        token = self._issue(
            test_tenant["id"],
            granted_user["id"],
            proxy_app["id"],
            f"{names['app_url']}/dash",
            names["domain"],
        )
        database.users.inactivate_user(test_tenant["id"], str(granted_user["id"]))
        try:
            resp = client.get(
                "/forward-auth/callback",
                params={"token": token},
                headers={"host": names["portal_host"]},
                follow_redirects=False,
            )
        finally:
            database.users.reactivate_user(test_tenant["id"], str(granted_user["id"]))
        assert resp.status_code == 403
        assert "set-cookie" not in {k.lower() for k in resp.headers}

    def test_single_use_replay_rejected(self, client, names, granted_user, proxy_app, test_tenant):
        token = self._issue(
            test_tenant["id"],
            granted_user["id"],
            proxy_app["id"],
            f"{names['app_url']}/dash",
            names["domain"],
        )
        first = client.get(
            "/forward-auth/callback",
            params={"token": token},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert first.status_code == 302
        replay = client.get(
            "/forward-auth/callback",
            params={"token": token},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert replay.status_code == 403

    def test_cross_domain_substitution_rejected(
        self, client, names, granted_user, proxy_app, test_tenant
    ):
        other_token = self._issue(
            test_tenant["id"],
            granted_user["id"],
            proxy_app["id"],
            f"{names['app_url']}/dash",
            "other-domain.example",  # bound to a DIFFERENT domain
        )
        resp = client.get(
            "/forward-auth/callback",
            params={"token": other_token},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_token_tenant_must_match_portal_tenant(self, client, names, verified_domain):
        # Defense-in-depth: even a successfully-redeemed token whose bound tenant
        # differs from the portal host's owning tenant is rejected at /callback.
        # (Unreachable by construction upstream -- the nonce FK + redeem's
        # tenant-match already guard -- so exercise it by mocking redeem.)
        fake_payload = {
            "tid": "00000000-0000-0000-0000-000000000099",
            "sub": "u1",
            "app": "a1",
            "rd": f"{names['app_url']}/dash",
        }
        with patch(
            "routers.forward_auth.runtime.forward_auth_service.redeem_authorization_token",
            return_value=fake_payload,
        ):
            resp = client.get(
                "/forward-auth/callback",
                params={"token": "anything"},
                headers={"host": names["portal_host"]},
                follow_redirects=False,
            )
        assert resp.status_code == 403

    def test_tampered_token_rejected(self, client, names, proxy_app):
        bad = mint_authorization_token(
            user_id="u1",
            tenant_id="t1",
            domain=names["domain"],
            app_id=str(proxy_app["id"]),
            rd=f"{names['app_url']}/dash",
            nonce="never-recorded",
        )
        resp = client.get(
            "/forward-auth/callback",
            params={"token": bad},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_callback_open_redirect_rd_rejected(
        self, client, names, granted_user, proxy_app, test_tenant
    ):
        token = self._issue(
            test_tenant["id"],
            granted_user["id"],
            proxy_app["id"],
            "https://evil.example/x",
            names["domain"],
        )
        resp = client.get(
            "/forward-auth/callback",
            params={"token": token},
            headers={"host": names["portal_host"]},
            follow_redirects=False,
        )
        assert resp.status_code == 403
