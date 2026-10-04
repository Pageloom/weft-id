"""Upstream OIDC ``form_post`` callback E2E (Sign in with Apple's shape, in a real browser).

Apple posts the authorization response to WeftID's callback from its own
site. The SameSite=Lax session cookie does not ride on that cross-site POST,
so the callback records the posted fields against the stored sign-in and
redirects (303) to the GET callback, which must arrive *with* the cookie for
the browser binding to hold. Unit tests cannot show what a browser sends;
this test does.

It reuses the loopback test bed (``app/dev/oidc_loopback_testbed.py``): the
relying-party tenant's connection points at WeftID's own OpenID Provider on
another tenant. When the provider answers the consent with a redirect back
to the callback (``?code=&state=``), Playwright rewrites that response into a
hop to a page on a different registrable domain (``appleid.cross-site.test``,
served by Playwright), which auto-submits the code and state as a form POST
to the real callback, as Apple does. Everything after that is the real server and the real browser.
"""

import json
import re
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from tests.e2e.test_oidc_upstream_loopback_e2e import (
    _event_count,
    _links,
    _rp_user_ids,
    _run_testbed,
)

_CROSS_SITE = "https://appleid.cross-site.test"

_FORM_POST_PAGE = """<!doctype html>
<html><body>
<form method="post" action="{action}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="code" value="{code}">
  <input type="hidden" name="user" value="{user}">
</form>
<script>document.forms[0].submit();</script>
</body></html>
"""


@pytest.fixture(scope="module")
def loopback_config():
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


def _html_attr(value: str) -> str:
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


class TestFormPostCallback:
    def test_cross_site_post_then_same_site_get_completes_sign_in(
        self, page, login, loopback_config
    ):
        op, rp = loopback_config["op"], loopback_config["rp"]
        connection_id = rp["connection_id"]
        callback = f"{rp['base_url']}/auth/oidc/{connection_id}/callback"

        assert _rp_user_ids(rp["tenant_id"], op["user_email"]) == []

        # The provider's redirect back to the callback (?code=&state=)
        # becomes a hop to the cross-site page instead. The redirect is
        # rewritten in the provider's response: Playwright does not route
        # the requests a browser makes by following a redirect.
        def _is_authorize(url: str) -> bool:
            return url.startswith(f"{op['base_url']}/oauth2/authorize")

        def _divert(route):
            response = route.fetch(max_redirects=0)
            location = response.headers.get("location", "")
            if not (location.startswith(f"{callback}?") and "code=" in location):
                route.fulfill(response=response)
                return
            params = parse_qs(urlparse(location).query)
            target = f"{_CROSS_SITE}/form-post?" + urlencode(
                {"state": params["state"][0], "code": params["code"][0]}
            )
            # A page that navigates on, not a 302: the consent form's CSP
            # form-action would block a redirect to an unlisted host.
            route.fulfill(
                status=200,
                content_type="text/html",
                body=f"<script>location.href = {json.dumps(target)};</script>",
            )

        def _serve_form_post(route):
            params = parse_qs(urlparse(route.request.url).query)
            route.fulfill(
                status=200,
                content_type="text/html",
                body=_FORM_POST_PAGE.format(
                    action=callback,
                    state=_html_attr(params["state"][0]),
                    code=_html_attr(params["code"][0]),
                    user=_html_attr(json.dumps({"name": {"firstName": "Ignored"}})),
                ),
            )

        page.route(_is_authorize, _divert)
        page.route(f"{_CROSS_SITE}/**", _serve_form_post)

        callback_requests = []
        page.on(
            "request",
            lambda request: (
                callback_requests.append(request)
                if request.url.split("?", 1)[0] == callback
                else None
            ),
        )

        # OP session, then start the sign-in on the RP directly.
        login(op["base_url"], op["user_email"])
        page.goto(f"{rp['base_url']}/auth/oidc/{connection_id}/login")
        consent_url = re.escape(f"{op['base_url']}/oauth2/authorize?")
        dashboard_url = re.escape(f"{rp['base_url']}/dashboard")
        page.wait_for_url(re.compile(f"^({consent_url}|{dashboard_url})"), timeout=15000)
        if "/oauth2/authorize" in page.url:
            page.wait_for_selector("button[name='action'][value='allow']", timeout=10000)
            page.locator("button[name='action'][value='allow']").click()

        page.wait_for_url(f"{rp['base_url']}/dashboard**", timeout=20000)
        assert "error=" not in page.url, f"Sign-in landed with an error: {page.url}"

        # The flow really went cross-site: POST without the session cookie,
        # then the redirected GET (state only) with it.
        posts = [r for r in callback_requests if r.method == "POST"]
        gets = [r for r in callback_requests if r.method == "GET" and "code=" not in r.url]
        assert len(posts) == 1, [r.url for r in callback_requests]
        assert len(gets) == 1, [r.url for r in callback_requests]
        post_cookies = posts[0].all_headers().get("cookie", "")
        get_cookies = gets[0].all_headers().get("cookie", "")
        assert "session=" not in post_cookies, post_cookies
        assert "session=" in get_cookies, "Lax session cookie missing on the redirected GET"
        assert parse_qs(urlparse(gets[0].url).query).keys() == {"state"}

        # The sign-in completed through the stored, posted code.
        user_ids = _rp_user_ids(rp["tenant_id"], op["user_email"])
        assert len(user_ids) == 1
        assert len(_links(connection_id)) == 1
        assert _event_count(rp["tenant_id"], "oidc_user_jit_provisioned") == 1
        assert _event_count(rp["tenant_id"], "oidc_login_failed") == 0
