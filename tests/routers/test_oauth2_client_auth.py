"""Token-endpoint client authentication methods (RFC 6749 section 2.3.1).

The token endpoint must accept ``client_secret_basic`` (HTTP Basic, the
spec-mandated method and the OIDC discovery default) as well as
``client_secret_post`` (form fields). Using both in one request, a malformed
Basic header, or no credentials at all must all fail closed as
``invalid_client``. These tests were added when the loopback upstream-OIDC E2E
(WeftID as its own upstream IdP) revealed that the relying-party side sends
Basic while the provider side only read form fields.
"""

import base64

import database
import pytest
from routers.oauth2 import _resolve_client_credentials
from starlette.requests import Request

REDIRECT_URI = "http://localhost:3000/callback"


def _basic_header(client_id: str, client_secret: str) -> dict[str, str]:
    raw = f"{client_id}:{client_secret}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


def _make_code(test_tenant, normal_oauth2_client, test_user) -> str:
    return database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=REDIRECT_URI,
    )


class TestTokenEndpointBasicAuth:
    def test_basic_auth_succeeds(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        code = _make_code(test_tenant, normal_oauth2_client, test_user)
        response = client.post(
            "/oauth2/token",
            headers={
                "Host": test_tenant_host,
                **_basic_header(
                    normal_oauth2_client["client_id"], normal_oauth2_client["client_secret"]
                ),
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert "access_token" in body
        assert body["token_type"] == "Bearer"

    def test_basic_auth_wrong_secret_rejected(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        code = _make_code(test_tenant, normal_oauth2_client, test_user)
        response = client.post(
            "/oauth2/token",
            headers={
                "Host": test_tenant_host,
                **_basic_header(normal_oauth2_client["client_id"], "not-the-secret"),
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_client"

    def test_basic_and_form_together_rejected(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """RFC 6749 section 2.3: at most one client authentication method."""
        code = _make_code(test_tenant, normal_oauth2_client, test_user)
        response = client.post(
            "/oauth2/token",
            headers={
                "Host": test_tenant_host,
                **_basic_header(
                    normal_oauth2_client["client_id"], normal_oauth2_client["client_secret"]
                ),
            },
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_client"

    def test_malformed_basic_header_rejected(self, client, test_tenant_host):
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host, "Authorization": "Basic not-base64!!"},
            data={"grant_type": "authorization_code", "code": "x", "redirect_uri": REDIRECT_URI},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_client"

    def test_missing_credentials_is_invalid_client_not_422(self, client, test_tenant_host):
        """Form fields are optional now; absent credentials must still be a
        clean OAuth2 error, never a validation 422."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={"grant_type": "authorization_code", "code": "x", "redirect_uri": REDIRECT_URI},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "invalid_client"

    def test_form_credentials_still_work(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """client_secret_post is unchanged."""
        code = _make_code(test_tenant, normal_oauth2_client, test_user)
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
        )
        assert response.status_code == 200, response.text


def _request(headers: dict[str, str] | None = None) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": raw})


class TestResolveClientCredentials:
    def test_basic_decodes_and_urldecodes(self):
        # Per RFC 6749 section 2.3.1 the id and secret are form-urlencoded
        # before base64; a literal ':' or '%' in the secret survives.
        encoded = base64.b64encode(b"my%3Aclient:s%25cret%3A1").decode()
        creds = _resolve_client_credentials(
            _request({"Authorization": f"Basic {encoded}"}), None, None
        )
        assert creds == ("my:client", "s%cret:1")

    def test_form_credentials(self):
        assert _resolve_client_credentials(_request(), "cid", "sec") == ("cid", "sec")

    def test_form_missing_half_is_none(self):
        assert _resolve_client_credentials(_request(), "cid", None) is None
        assert _resolve_client_credentials(_request(), None, "sec") is None

    def test_nothing_is_none(self):
        assert _resolve_client_credentials(_request(), None, None) is None

    def test_both_methods_is_none(self):
        encoded = base64.b64encode(b"cid:sec").decode()
        req = _request({"Authorization": f"Basic {encoded}"})
        assert _resolve_client_credentials(req, "cid", None) is None
        assert _resolve_client_credentials(req, None, "sec") is None

    @pytest.mark.parametrize(
        "header",
        [
            "Basic",  # no payload
            "Basic ",  # empty payload
            "Basic @@@",  # not base64
            f"Basic {base64.b64encode(b'no-colon').decode()}",  # no separator
            f"Basic {base64.b64encode(b':sec').decode()}",  # empty id
            f"Basic {base64.b64encode(b'cid:').decode()}",  # empty secret
            f"Basic {base64.b64encode(b'\xff\xfe:x').decode()}",  # not utf-8
        ],
    )
    def test_malformed_basic_is_none(self, header):
        assert _resolve_client_credentials(_request({"Authorization": header}), None, None) is None

    def test_over_long_basic_is_none(self):
        long_secret = "x" * 256
        encoded = base64.b64encode(f"cid:{long_secret}".encode()).decode()
        req = _request({"Authorization": f"Basic {encoded}"})
        assert _resolve_client_credentials(req, None, None) is None

    def test_bearer_header_is_ignored(self):
        # A Bearer header is not client authentication; fall through to form.
        req = _request({"Authorization": "Bearer token"})
        assert _resolve_client_credentials(req, "cid", "sec") == ("cid", "sec")
        assert _resolve_client_credentials(req, None, None) is None
