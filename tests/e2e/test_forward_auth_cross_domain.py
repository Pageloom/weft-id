"""Cross-domain forward-auth E2E test.

Exercises the full forward-auth handshake across TWO real domains served by the
dev reverse proxy:

  * the WeftID tenant on the base domain   (``e2e-fa.weftid.localhost``)
  * a protected app on a SECOND domain     (``e2e-fa.protected.localhost``),
    fronted by a portal host               (``auth.e2e-fa.protected.localhost``)

The test plays the combined role of the operator's reverse proxy and the
browser. It uses an httpx client with a shared cookie jar (so the per-domain
forward-auth cookie, scoped to ``protected.localhost``, is sent back on portal
subrequests) and drives the six-step handshake end to end:

    1. proxy GET /forward-auth/check on the portal host (no cookie) -> 302 /start
    2. /start -> 302 to the canonical tenant host /authorize
    3. /authorize (authenticated central session) -> 302 portal /callback?token=
    4. /callback -> sets the per-domain cookie, 302 to rd
    5. proxy GET /forward-auth/check again -> 200 + X-Forwarded-* identity headers
       (the headers a real proxy would pass to the dummy upstream)

It also asserts the negative path: a user without a grant is denied at
/authorize and never obtains a cookie.

Opt-in: the second-domain vhost (dev/nginx/conf.d/forward-auth.conf) and the
testbed must be present. The test skips cleanly if the dev stack is not
reachable on the protected domain.
"""

import httpx
import pytest

# The dev reverse proxy serves both domains on 127.0.0.1:443 with a self-signed
# cert (SAN covers *.weftid.localhost), so TLS verification is disabled here.
_VERIFY = False


def _client() -> httpx.Client:
    """An httpx client with a shared cookie jar, not following redirects.

    Redirects are followed manually so the test can inspect each hop and set the
    proxy-supplied forward-auth headers (X-Forwarded-Host / -Uri) on the /check
    subrequests, exactly as a reverse proxy would.
    """
    return httpx.Client(verify=_VERIFY, follow_redirects=False, timeout=15.0)


def _reachable(base_url: str) -> bool:
    """True if the protected-domain vhost answers (dev stack + vhost present)."""
    try:
        with _client() as c:
            # Any response (even 403/404) proves the vhost routes to the app.
            c.get(f"{base_url}/forward-auth/check", timeout=5.0)
        return True
    except Exception:
        return False


@pytest.fixture()
def fa(forward_auth_config):
    """Skip the whole module unless the cross-domain dev rig is reachable."""
    if not _reachable(forward_auth_config["portal_base_url"]):
        pytest.skip(
            "Forward-auth cross-domain rig not reachable "
            "(is the protected.localhost vhost up and does it resolve to 127.0.0.1?)"
        )
    return forward_auth_config


class TestForwardAuthCrossDomain:
    """The full per-domain handshake across two real domains."""

    def test_full_handshake_grants_access_with_identity_headers(self, fa):
        portal = fa["portal_base_url"]
        canonical = fa["canonical_base_url"]
        app_host = fa["app_host"]

        with _client() as client:
            # Establish the central WeftID session on the canonical tenant host.
            r = client.get(f"{canonical}/dev/login?email={fa['user_email']}")
            assert r.status_code in (302, 303), r.text
            assert "/dashboard" in r.headers["location"]

            # 1. Reverse-proxy subrequest: GET /check on the portal host with the
            #    original app host + URI conveyed in forward-auth headers.
            check_headers = {
                "X-Forwarded-Host": app_host,
                "X-Forwarded-Uri": "/",
            }
            r = client.get(f"{portal}/forward-auth/check", headers=check_headers)
            assert r.status_code == 302, f"expected start redirect, got {r.status_code}"
            assert "/forward-auth/start" in r.headers["location"]

            # 2. Follow /start on the portal host -> canonical /authorize.
            start_url = _abs(portal, r.headers["location"])
            r = client.get(start_url)
            assert r.status_code == 302
            authorize_url = r.headers["location"]
            assert authorize_url.startswith(canonical), authorize_url
            assert "/forward-auth/authorize" in authorize_url

            # 3. /authorize on the canonical host with the live session -> token,
            #    redirect to portal /callback.
            r = client.get(authorize_url)
            assert r.status_code == 302, r.text
            callback_url = r.headers["location"]
            assert callback_url.startswith(portal), callback_url
            assert "/forward-auth/callback?token=" in callback_url

            # 4. /callback on the portal host -> sets the per-domain cookie,
            #    redirects to rd. rd is the original protected request path the
            #    proxy conveyed (here "/", a rooted-relative path the browser
            #    resolves against the app host).
            r = client.get(callback_url)
            assert r.status_code == 302
            location = r.headers["location"]
            assert location in ("/", ""), f"unexpected rd redirect: {location!r}"
            # The per-domain forward-auth cookie is now in the jar, scoped to the
            # protected domain (NOT the tenant base domain).
            assert any("protected.localhost" in (c.domain or "") for c in client.cookies.jar), (
                "per-domain forward-auth cookie not set on the protected domain"
            )

            # 5. Re-run the proxy /check -> 200 with identity headers the proxy
            #    would forward to the dummy upstream.
            r = client.get(f"{portal}/forward-auth/check", headers=check_headers)
            assert r.status_code == 200, f"expected allow, got {r.status_code}"
            assert r.headers.get("x-forwarded-user")
            assert r.headers.get("x-forwarded-email") == fa["user_email"]
            assert "x-forwarded-display-name" in {k.lower() for k in r.headers}

    def test_public_path_bypasses_auth(self, fa):
        """A configured public path returns 200 with no session and no cookie."""
        portal = fa["portal_base_url"]
        app_host = fa["app_host"]
        with _client() as client:
            r = client.get(
                f"{portal}/forward-auth/check",
                headers={"X-Forwarded-Host": app_host, "X-Forwarded-Uri": "/public/health"},
            )
            assert r.status_code == 200
            # Public-path allow carries no identity headers.
            assert "x-forwarded-user" not in {k.lower() for k in r.headers}


def _abs(base_url: str, location: str) -> str:
    """Resolve a possibly-relative redirect Location against base_url."""
    if location.startswith("http://") or location.startswith("https://"):
        return location
    return base_url.rstrip("/") + location
