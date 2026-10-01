"""IdP-initiated SAML Single Logout at WeftID's SP endpoint (``/saml/slo``).

The upstream IdP sends a LogoutRequest through the browser. WeftID verifies it
(signature over the redirect binding's query or the POST binding's enveloped
XML signature, issuer, destination, expiry), ends the WeftID session when it
is the one named (IdP, NameID, SessionIndex), and returns the browser to the
IdP with a signed LogoutResponse. Rejected requests end nothing and are
audited. Also the upstream SAML session keys carried through the platform MFA
step, which is what lets a SAML+MFA session be matched at all.

Real database (tenant, IdP, SP certificate, events, revocation) and real
signatures throughout.
"""

import base64
import datetime
import time
import zlib
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import database
import pytest
from lxml import etree
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.logout_request import OneLogin_Saml2_Logout_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from routers.auth import _login_completion
from starlette.requests import Request
from utils.saml import (
    build_saml_settings,
    encrypt_private_key,
    generate_sp_certificate,
    get_certificate_expiry,
)
from utils.saml_slo import _sign_element
from utils.session import SESSION_ID_KEY

IDP_ENTITY_ID = "https://saml-idp.example/entity"
IDP_SLO_URL = "https://saml-idp.example/slo"
NAME_ID = "slo-user@example.com"
SESSION_INDEX = "_session-index-1"
SID = "saml-slo-sid"

_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"


@pytest.fixture(scope="module")
def idp_keys() -> tuple[str, str]:
    return generate_sp_certificate(tenant_id="slo-idp")


@pytest.fixture(scope="module")
def sp_keys() -> tuple[str, str]:
    return generate_sp_certificate(tenant_id="slo-sp")


@pytest.fixture
def saml_idp(test_tenant, test_admin_user, idp_keys, sp_keys, test_tenant_host):
    tid = str(test_tenant["id"])
    idp = database.saml.create_identity_provider(
        tid,
        tid,
        name=f"SLO IdP {uuid4().hex[:6]}",
        provider_type="generic",
        sp_entity_id=f"https://{test_tenant_host}/saml/metadata",
        created_by=str(test_admin_user["id"]),
        entity_id=IDP_ENTITY_ID,
        sso_url="https://saml-idp.example/sso",
        certificate_pem=idp_keys[0],
        slo_url=IDP_SLO_URL,
        is_enabled=True,
    )
    database.saml.create_idp_sp_certificate(
        tid,
        str(idp["id"]),
        tid,
        certificate_pem=sp_keys[0],
        private_key_pem_enc=encrypt_private_key(sp_keys[1]),
        expires_at=get_certificate_expiry(sp_keys[0]),
        created_by=str(test_admin_user["id"]),
    )
    return idp


@pytest.fixture
def session_data(mocker) -> dict:
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


@pytest.fixture
def http(client, test_tenant_host, session_data):
    class _Client:
        def get(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.get(url, headers={"Host": test_tenant_host}, **kw)

        def post(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.post(url, headers={"Host": test_tenant_host}, **kw)

    return _Client()


@pytest.fixture
def signed_in(session_data, saml_idp, test_user):
    """A browser session that came from ``saml_idp`` as NAME_ID / SESSION_INDEX."""
    session_data.update(
        {
            "user_id": str(test_user["id"]),
            "session_start": int(time.time()),
            SESSION_ID_KEY: SID,
            "saml_idp_id": str(saml_idp["id"]),
            "saml_name_id": NAME_ID,
            "saml_session_index": SESSION_INDEX,
        }
    )
    return session_data


def _slo_url(host: str) -> str:
    return f"https://{host}/saml/slo"


def _post_request(
    host: str,
    keys: tuple[str, str],
    *,
    name_id: str = NAME_ID,
    session_index: str | None = SESSION_INDEX,
    destination: str | None = None,
    issuer: str = IDP_ENTITY_ID,
    not_on_or_after: datetime.datetime | None = None,
    sign: bool = True,
    tamper=None,
) -> str:
    """A LogoutRequest for the POST binding (base64, enveloped signature)."""
    now = datetime.datetime.now(datetime.UTC)
    expiry = not_on_or_after or now + datetime.timedelta(minutes=5)
    request = etree.Element(
        f"{{{_SAMLP}}}LogoutRequest",
        attrib={
            "ID": f"_{uuid4().hex}",
            "Version": "2.0",
            "IssueInstant": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Destination": destination or _slo_url(host),
            "NotOnOrAfter": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        nsmap={"samlp": _SAMLP, "saml": _SAML},
    )
    etree.SubElement(request, f"{{{_SAML}}}Issuer").text = issuer
    etree.SubElement(request, f"{{{_SAML}}}NameID").text = name_id
    if session_index:
        etree.SubElement(request, f"{{{_SAMLP}}}SessionIndex").text = session_index
    if sign:
        _sign_element(request, keys[0], keys[1])
    if tamper:
        tamper(request)
    return base64.b64encode(
        etree.tostring(request, xml_declaration=True, encoding="UTF-8")
    ).decode()


def _idp_role_settings(host: str, keys: tuple[str, str]) -> dict:
    """python3-saml settings with the IdP in the "sp" seat, to sign as it."""
    return build_saml_settings(
        sp_entity_id=IDP_ENTITY_ID,
        sp_acs_url="https://saml-idp.example/acs",
        sp_certificate_pem=keys[0],
        sp_private_key_pem=keys[1],
        idp_entity_id="urn:weftid:sp",
        idp_sso_url="https://unused.example/sso",
        idp_certificate_pem=keys[0],
        idp_slo_url=_slo_url(host),
    )


def _redirect_query(
    host: str,
    keys: tuple[str, str],
    *,
    relay_state: str | None = None,
    sign: bool = True,
    name_id: str = NAME_ID,
) -> str:
    """The query string of an HTTP-Redirect binding LogoutRequest."""
    settings = _idp_role_settings(host, keys)
    logout_request = OneLogin_Saml2_Logout_Request(
        OneLogin_Saml2_Settings(settings), name_id=name_id, session_index=SESSION_INDEX
    )
    parameters = {"SAMLRequest": logout_request.get_request()}
    if relay_state:
        parameters["RelayState"] = relay_state
    if sign:
        auth = OneLogin_Saml2_Auth({"http_host": "", "script_name": "", "get_data": {}}, settings)
        auth.add_request_signature(parameters)
    return urlsplit(OneLogin_Saml2_Utils.redirect(_slo_url(host), parameters)).query


def _events(test_tenant, event_type: str) -> list[dict]:
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=30)
        if e["event_type"] == event_type
    ]


def _verify_redirect_signature(location: str, signer_cert: str, saml_type: str) -> dict:
    """Check an HTTP-Redirect binding signature the way a receiving party would."""
    parts = urlsplit(location)
    get_data = {key: values[0] for key, values in parse_qs(parts.query).items()}
    settings = build_saml_settings(
        sp_entity_id="urn:receiver",
        sp_acs_url="https://receiver.example/acs",
        sp_certificate_pem=signer_cert,
        sp_private_key_pem=generate_sp_certificate(tenant_id="receiver")[1],
        idp_entity_id="urn:signer",
        idp_sso_url="https://signer.example/sso",
        idp_certificate_pem=signer_cert,
    )
    auth = OneLogin_Saml2_Auth(
        {
            "http_host": "",
            "script_name": "",
            "get_data": get_data,
            "query_string": parts.query,
            "validate_signature_from_qs": True,
        },
        settings,
    )
    assert "Signature" in get_data
    assert auth._validate_signature(get_data, saml_type)
    return get_data


def _assert_signed_response(location: str, sp_keys, relay_state: str | None = None) -> str:
    """The LogoutResponse redirect is to the IdP, signed, and echoes RelayState."""
    assert location.startswith(f"{IDP_SLO_URL}?")
    get_data = _verify_redirect_signature(location, sp_keys[0], "SAMLResponse")
    assert set(get_data) == {"SAMLResponse", "SigAlg", "Signature"} | (
        {"RelayState"} if relay_state else set()
    )
    if relay_state:
        assert get_data["RelayState"] == relay_state
    xml = zlib.decompress(base64.b64decode(get_data["SAMLResponse"]), -15).decode()
    assert "urn:oasis:names:tc:SAML:2.0:status:Success" in xml
    return xml


# ============================================================================
# Session ended
# ============================================================================


class TestNamedSessionEnds:
    def test_redirect_binding(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys, sp_keys, saml_idp
    ):
        query = _redirect_query(test_tenant_host, idp_keys, relay_state="rs-1")

        response = http.get(f"/saml/slo?{query}")

        assert response.status_code == 303
        _assert_signed_response(response.headers["location"], sp_keys, relay_state="rs-1")
        assert "user_id" not in signed_in
        assert database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), SID)
        event = _events(test_tenant, "user_signed_out")[0]
        assert event["metadata"]["reason"] == "upstream_saml_slo"
        assert event["metadata"]["saml_idp_id"] == str(saml_idp["id"])

    def test_post_binding(self, http, signed_in, test_tenant, test_tenant_host, idp_keys, sp_keys):
        response = http.post(
            "/saml/slo",
            data={
                "SAMLRequest": _post_request(test_tenant_host, idp_keys),
                "RelayState": "rs-2",
            },
        )

        assert response.status_code == 303
        xml = _assert_signed_response(response.headers["location"], sp_keys, relay_state="rs-2")
        assert "InResponseTo=" in xml
        assert "user_id" not in signed_in
        assert database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), SID)

    def test_request_without_session_index_ends_every_session_of_the_name_id(
        self, http, signed_in, test_tenant_host, idp_keys
    ):
        http.post(
            "/saml/slo",
            data={"SAMLRequest": _post_request(test_tenant_host, idp_keys, session_index=None)},
        )
        assert "user_id" not in signed_in

    def test_frontchannel_rps_load_before_returning_to_the_idp(
        self, http, signed_in, test_tenant_host, idp_keys, mocker
    ):
        from services.oidc import OidcSessionEnd

        mocker.patch(
            "routers.auth.logout.end_oidc_session_quietly",
            return_value=OidcSessionEnd(frontchannel_logout_urls=["https://rp.example/fc"]),
        )
        response = http.post(
            "/saml/slo", data={"SAMLRequest": _post_request(test_tenant_host, idp_keys)}
        )
        assert response.status_code == 200
        assert 'src="https://rp.example/fc"' in response.text
        assert IDP_SLO_URL in response.text


# ============================================================================
# Valid request, but not this browser's session: answered, nothing ended
# ============================================================================


class TestOtherSessionKept:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"name_id": "someone-else@example.com"},
            {"session_index": "_another-session"},
        ],
    )
    def test_request_for_another_session(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys, sp_keys, overrides
    ):
        response = http.post(
            "/saml/slo",
            data={"SAMLRequest": _post_request(test_tenant_host, idp_keys, **overrides)},
        )
        _assert_signed_response(response.headers["location"], sp_keys)
        assert signed_in["user_id"]
        assert not database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), SID)

    def test_session_from_another_idp(self, http, signed_in, test_tenant_host, idp_keys, sp_keys):
        signed_in["saml_idp_id"] = str(uuid4())
        response = http.post(
            "/saml/slo", data={"SAMLRequest": _post_request(test_tenant_host, idp_keys)}
        )
        _assert_signed_response(response.headers["location"], sp_keys)
        assert signed_in["user_id"]

    def test_password_session_is_not_touched(
        self, http, session_data, test_user, test_tenant_host, idp_keys, saml_idp
    ):
        session_data.update({"user_id": str(test_user["id"]), SESSION_ID_KEY: SID})
        http.post("/saml/slo", data={"SAMLRequest": _post_request(test_tenant_host, idp_keys)})
        assert session_data["user_id"] == str(test_user["id"])

    def test_server_to_server_request_is_answered(
        self, http, session_data, test_tenant_host, idp_keys, sp_keys, saml_idp
    ):
        response = http.post(
            "/saml/slo", data={"SAMLRequest": _post_request(test_tenant_host, idp_keys)}
        )
        _assert_signed_response(response.headers["location"], sp_keys)
        assert session_data == {}


# ============================================================================
# Rejected: nothing ended, audited
# ============================================================================


def _other_keys():
    return generate_sp_certificate(tenant_id="forger")


def _move_id(request):
    request.set("ID", "_moved")


def _duplicate_id(request):
    extensions = etree.SubElement(request, f"{{{_SAMLP}}}Extensions")
    etree.SubElement(extensions, "dup", attrib={"ID": request.get("ID")})


class TestRejected:
    @pytest.mark.parametrize(
        ("build", "reason"),
        [
            (lambda host, keys: {"SAMLRequest": _post_request(host, keys, sign=False)}, "unsigned"),
            (
                lambda host, keys: {"SAMLRequest": _post_request(host, _other_keys())},
                "signature",
            ),
            (
                lambda host, keys: {"SAMLRequest": _post_request(host, keys, tamper=_move_id)},
                "signature_reference",
            ),
            (
                lambda host, keys: {"SAMLRequest": _post_request(host, keys, tamper=_duplicate_id)},
                "signature_reference",
            ),
            (
                lambda host, keys: {
                    "SAMLRequest": _post_request(
                        host, keys, destination="https://elsewhere.example/saml/slo"
                    )
                },
                "invalid",
            ),
            (
                lambda host, keys: {
                    "SAMLRequest": _post_request(
                        host,
                        keys,
                        not_on_or_after=datetime.datetime.now(datetime.UTC)
                        - datetime.timedelta(minutes=1),
                    )
                },
                "invalid",
            ),
        ],
        ids=["unsigned", "wrong-key", "moved-id", "duplicate-id", "destination", "expired"],
    )
    def test_post_binding(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys, saml_idp, build, reason
    ):
        response = http.post("/saml/slo", data=build(test_tenant_host, idp_keys))

        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]
        assert not database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), SID)
        event = _events(test_tenant, "saml_idp_logout_rejected")[0]
        assert str(event["artifact_id"]) == str(saml_idp["id"])
        assert event["metadata"]["reason"] == reason

    def test_unsigned_redirect_binding(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys
    ):
        response = http.get(f"/saml/slo?{_redirect_query(test_tenant_host, idp_keys, sign=False)}")
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]
        assert _events(test_tenant, "saml_idp_logout_rejected")[0]["metadata"]["reason"] == (
            "unsigned"
        )

    def test_redirect_binding_signed_by_another_key(
        self, http, signed_in, test_tenant, test_tenant_host
    ):
        query = _redirect_query(test_tenant_host, _other_keys())
        response = http.get(f"/saml/slo?{query}")
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]
        assert _events(test_tenant, "saml_idp_logout_rejected")[0]["metadata"]["reason"] == (
            "signature"
        )

    def test_redirect_binding_with_altered_query(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys
    ):
        query = _redirect_query(test_tenant_host, idp_keys, relay_state="original")
        response = http.get(f"/saml/slo?{query.replace('original', 'altered')}")
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]

    def test_unknown_issuer_is_not_audited(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys, saml_idp
    ):
        response = http.post(
            "/saml/slo",
            data={
                "SAMLRequest": _post_request(
                    test_tenant_host, idp_keys, issuer="https://stranger.example"
                )
            },
        )
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]
        assert _events(test_tenant, "saml_idp_logout_rejected") == []

    @pytest.mark.parametrize("garbage", ["not base64 at all!", base64.b64encode(b"<x/>").decode()])
    def test_malformed_request(self, http, signed_in, saml_idp, garbage):
        response = http.post("/saml/slo", data={"SAMLRequest": garbage})
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]

    def test_idp_without_slo_url_is_refused(
        self, http, signed_in, test_tenant, test_tenant_host, idp_keys, saml_idp
    ):
        database.saml.update_identity_provider(
            str(test_tenant["id"]), str(saml_idp["id"]), slo_url=""
        )
        response = http.post(
            "/saml/slo", data={"SAMLRequest": _post_request(test_tenant_host, idp_keys)}
        )
        assert response.headers["location"] == "/login"
        assert signed_in["user_id"]


# ============================================================================
# SP-initiated SLO is signed
# ============================================================================


def test_sp_initiated_logout_request_is_signed(test_tenant, test_tenant_host, saml_idp, sp_keys):
    from services.saml import initiate_sp_logout

    url = initiate_sp_logout(
        tenant_id=str(test_tenant["id"]),
        saml_idp_id=str(saml_idp["id"]),
        name_id=NAME_ID,
        name_id_format=None,
        session_index=SESSION_INDEX,
        base_url=f"https://{test_tenant_host}",
    )
    assert url.startswith(f"{IDP_SLO_URL}?")
    _verify_redirect_signature(url, sp_keys[0], "SAMLRequest")


# ============================================================================
# The SAML session keys survive the platform MFA step
# ============================================================================


def _request(session: dict) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mfa/verify",
            "headers": [],
            "query_string": b"",
            "scheme": "https",
            "server": ("test", 443),
            "client": ("203.0.113.9", 1234),
            "session": session,
        }
    )


class TestSamlKeysThroughMfa:
    _DATA = {
        "saml_idp_id": "idp-1",
        "saml_name_id": NAME_ID,
        "saml_name_id_format": None,
        "saml_session_index": SESSION_INDEX,
        "saml_slo_url": IDP_SLO_URL,
    }

    def _complete(self, test_tenant, test_user, session):
        request = _request(session)
        _login_completion.complete_authenticated_login(
            request, str(test_tenant["id"]), str(test_user["id"]), mfa_method="email"
        )
        return request.session

    def test_keys_are_restored_after_regeneration(self, test_tenant, test_user):
        session: dict = {}
        _login_completion.stash_upstream_saml_session(
            session, user_id=str(test_user["id"]), saml_session_data=self._DATA
        )
        after = self._complete(test_tenant, test_user, session)
        for key, value in self._DATA.items():
            assert after.get(key) == value
        assert _login_completion.PENDING_UPSTREAM_SAML_SESSION_KEY not in after

    @pytest.mark.parametrize(
        "overrides",
        [
            {"user_id": "someone-else"},
            {"at": int(time.time()) - 16 * 60},
            {"at": "yesterday"},
            {"saml_idp_id": None},
        ],
    )
    def test_foreign_stale_or_malformed_stash_is_dropped(self, test_tenant, test_user, overrides):
        session: dict = {}
        _login_completion.stash_upstream_saml_session(
            session, user_id=str(test_user["id"]), saml_session_data=self._DATA
        )
        session[_login_completion.PENDING_UPSTREAM_SAML_SESSION_KEY].update(overrides)
        after = self._complete(test_tenant, test_user, session)
        assert "saml_name_id" not in after
        assert _login_completion.PENDING_UPSTREAM_SAML_SESSION_KEY not in after

    def test_non_dict_stash_is_dropped(self, test_tenant, test_user):
        session: dict = {_login_completion.PENDING_UPSTREAM_SAML_SESSION_KEY: "x"}
        after = self._complete(test_tenant, test_user, session)
        assert "saml_idp_id" not in after


def test_acs_mfa_detour_stashes_the_saml_session_keys(http, session_data, mocker):
    """The ACS keeps the keys Single Logout matches on across the MFA step."""
    from unittest.mock import MagicMock

    result = MagicMock()
    result.requires_mfa = True
    result.idp_id = "idp-1"
    result.attributes.name_id = NAME_ID
    result.name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    result.session_index = SESSION_INDEX
    result.slo_url = IDP_SLO_URL
    mocker.patch(
        "routers.saml.authentication.saml_service.process_saml_response", return_value=result
    )
    mocker.patch(
        "routers.saml.authentication.saml_service.authenticate_via_saml",
        return_value={"id": "user-1", "mfa_method": "totp"},
    )

    response = http.post(
        f"/saml/acs/{uuid4()}", data={"SAMLResponse": "x", "RelayState": "/dashboard"}
    )

    assert response.headers["location"] == "/mfa/verify"
    stash = session_data[_login_completion.PENDING_UPSTREAM_SAML_SESSION_KEY]
    assert stash["user_id"] == "user-1"
    assert stash["saml_idp_id"] == "idp-1"
    assert stash["saml_name_id"] == NAME_ID
    assert stash["saml_session_index"] == SESSION_INDEX
    assert stash["saml_slo_url"] == IDP_SLO_URL
