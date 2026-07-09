"""E2E test for the OIDC provider happy path.

Drives a real browser through the full downstream OIDC flow against the
dev stack, crossing both auth boundaries the TestClient integration tests
cannot exercise together:

  1. /oauth2/authorize + consent  -- real session cookie in a real browser
  2. /oauth2/token                -- code exchange over HTTPS (httpx)
  3. ID-token verification        -- against the published JWKS, kid-selected
  4. /userinfo                    -- bearer access token boundary

Uses the oidc_testbed fixture (tenant + member user + OIDC-enabled client).
"""

import json
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

# The dev reverse proxy serves the tenant on 127.0.0.1:443 with a self-signed
# cert (SAN covers *.weftid.localhost), so TLS verification is disabled here.
_VERIFY = False

STATE = "e2e-state-42"
NONCE = "e2e-nonce-42"


def _authorize_url(cfg: dict) -> str:
    query = urlencode(
        {
            "client_id": cfg["client_id"],
            "redirect_uri": cfg["redirect_uri"],
            "scope": "openid profile email",
            "state": STATE,
            "nonce": NONCE,
        }
    )
    return f"{cfg['base_url']}/oauth2/authorize?{query}"


class TestOidcProviderHappyPath:
    def test_authorize_token_userinfo_round_trip(self, page, login, oidc_config):
        cfg = oidc_config
        base_url = cfg["base_url"]

        # --- 1. Browser: establish a session and request authorization.
        login(base_url, cfg["user_email"])

        page.goto(_authorize_url(cfg))

        # The consent page lists the requested scopes; approve it.
        page.wait_for_selector("button[name='action'][value='allow']", timeout=10000)
        assert "openid" in page.content()
        page.locator("button[name='action'][value='allow']").click()

        # The browser lands on the RP callback with code + echoed state.
        page.wait_for_url(f"{cfg['redirect_uri']}?*", timeout=10000)
        params = parse_qs(urlparse(page.url).query)
        assert params["state"] == [STATE]
        code = params["code"][0]
        assert code

        # --- 2. RP backend: exchange the code for tokens.
        with httpx.Client(verify=_VERIFY, timeout=15.0) as client:
            token_resp = client.post(
                f"{base_url}/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": cfg["client_id"],
                    "client_secret": cfg["client_secret"],
                    "code": code,
                    "redirect_uri": cfg["redirect_uri"],
                },
            )
            assert token_resp.status_code == 200, token_resp.text
            tokens = token_resp.json()
            assert tokens["token_type"].lower() == "bearer"
            access_token = tokens["access_token"]
            id_token = tokens["id_token"]

            # --- 3. Verify the ID token against the published JWKS.
            jwks = client.get(f"{base_url}/.well-known/jwks.json").json()
            kid = jwt.get_unverified_header(id_token)["kid"]
            entry = next(k for k in jwks["keys"] if k["kid"] == kid)
            public_key = RSAAlgorithm.from_jwk(json.dumps(entry))
            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=cfg["client_id"],
                issuer=base_url,
            )
            assert claims["nonce"] == NONCE
            assert claims["email"] == cfg["user_email"]
            assert claims["sub"]  # stable user id, never the email
            assert claims["sub"] != cfg["user_email"]

            # --- 4. Bearer boundary: userinfo returns the same subject.
            userinfo_resp = client.get(
                f"{base_url}/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            assert userinfo_resp.status_code == 200, userinfo_resp.text
            userinfo = userinfo_resp.json()
            assert userinfo["sub"] == claims["sub"]
            assert userinfo["email"] == cfg["user_email"]
