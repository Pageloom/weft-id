"""CSRF-aware TestClient for the real application.

``CSRFMiddleware`` rejects every session-cookie POST/PUT/PATCH/DELETE that
does not carry a token matching the one in the signed session cookie. Router
tests call those routes directly, without first rendering the form that would
have minted a token, so this client does the minting for them:

1. Before each state-changing request it decodes the client's current session
   cookie (or starts an empty one), inserts a fixed test token under the CSRF
   session key if it is not already there, re-signs the cookie with the app's
   real session key, and stores it back in the cookie jar. Existing session
   state (login, MFA, pending flows) is preserved.
2. It adds the ``X-CSRF-Token`` header with that token unless the test set the
   header itself.

Only requests to the real ``main.app`` are touched; a ``TestClient`` built on
an ad-hoc FastAPI app (middleware unit tests) behaves exactly like the
upstream class.

To exercise the negative path (a request that must be rejected), disable the
automation for a block::

    with client.without_csrf():
        response = client.post("/logout")
    assert response.status_code == 403

or send a deliberately wrong header, which overrides the automatic one.

Import this in place of ``fastapi.testclient.TestClient``::

    from tests.helpers.client import TestClient
"""

import base64
import http.cookiejar
import json
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import itsdangerous
from fastapi.testclient import TestClient as _UpstreamTestClient
from middleware.csrf import CSRF_HEADER_NAME, CSRF_PROTECTED_METHODS, CSRF_SESSION_KEY

# Any string works; the middleware compares it against the session value.
TEST_CSRF_TOKEN = "test-suite-csrf-token"

SESSION_COOKIE_NAME = "session"


def _real_app() -> Any:
    from main import app

    return app


def _signer() -> itsdangerous.TimestampSigner:
    """The same signer ``DynamicSessionMiddleware`` is configured with."""
    from utils.crypto import derive_session_key

    return itsdangerous.TimestampSigner(str(derive_session_key()))


def decode_session_cookie(value: str) -> dict[str, Any]:
    """Decode a Starlette session cookie value into its dict (unsigned)."""
    data = _signer().unsign(value.encode("utf-8"), max_age=14 * 24 * 60 * 60)
    decoded: dict[str, Any] = json.loads(base64.b64decode(data))
    return decoded


def encode_session_cookie(session: dict[str, Any]) -> str:
    """Sign a session dict exactly as Starlette's ``SessionMiddleware`` does."""
    data = base64.b64encode(json.dumps(session).encode("utf-8"))
    return _signer().sign(data).decode("utf-8")


class TestClient(_UpstreamTestClient):
    """``fastapi.testclient.TestClient`` that satisfies CSRF on the real app."""

    __test__ = False  # not a pytest test class

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._csrf_auto = True

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @contextmanager
    def without_csrf(self) -> Iterator[None]:
        """Send state-changing requests as-is: no cookie seeding, no header."""
        previous = self._csrf_auto
        self._csrf_auto = False
        try:
            yield
        finally:
            self._csrf_auto = previous

    def session_cookie(self) -> dict[str, Any]:
        """The decoded contents of the client's current session cookie."""
        value = self.cookies.get(SESSION_COOKIE_NAME, domain=self._cookie_domain())
        if value is None:
            return {}
        return decode_session_cookie(value)

    def set_session_cookie(self, session: dict[str, Any]) -> None:
        """Replace the client's session cookie with a signed copy of ``session``."""
        self.cookies.set(
            SESSION_COOKIE_NAME, encode_session_cookie(session), domain=self._cookie_domain()
        )

    def _cookie_domain(self) -> str:
        """The jar domain http.cookiejar files the app's own Set-Cookie under.

        Storing the seeded cookie under the same key means the app's later
        Set-Cookie replaces it instead of creating a second entry (a dotless
        host such as ``testserver`` is filed as ``testserver.local``; naming
        the bare host would add an entry the jar never sends).
        """
        return http.cookiejar.eff_request_host(urllib.request.Request(str(self.base_url)))[1]

    def seed_csrf_token(self, token: str = TEST_CSRF_TOKEN) -> str:
        """Ensure the session cookie carries ``token`` under the CSRF key."""
        session = self.session_cookie()
        if session.get(CSRF_SESSION_KEY) != token:
            session[CSRF_SESSION_KEY] = token
            self.set_session_cookie(session)
        return token

    # ------------------------------------------------------------------
    # httpx entry point
    # ------------------------------------------------------------------

    def request(self, method: str, url: Any, *args: Any, **kwargs: Any) -> httpx.Response:
        if self._csrf_auto and method.upper() in CSRF_PROTECTED_METHODS and self.app is _real_app():
            self.seed_csrf_token()
            headers = httpx.Headers(kwargs.get("headers"))
            if CSRF_HEADER_NAME not in headers:
                headers[CSRF_HEADER_NAME] = TEST_CSRF_TOKEN
            kwargs["headers"] = headers
        return super().request(method, url, *args, **kwargs)
