"""SAML IdP endpoints honour server-side session revocation.

The SAML IdP SSO endpoints read the session directly instead of through the
``require_current_user`` dependency. They now resolve the user with
``session_user_id`` (the same checks as every authenticated page), so a
revoked, timed-out, or deactivated session cannot mint an assertion. The
switch-account and SP-initiated SLO sign-outs revoke the session they end.
Real database throughout (tenant, user, revocation rows); the SP lookup is
patched.
"""

import time
from unittest.mock import patch

import database
import pytest
from routers.saml_idp._helpers import PENDING_SSO_KEYS
from utils.session import SESSION_ID_KEY

from tests.routers.test_saml_idp_sso import (
    _encode_redirect,
    _make_authn_request_xml,
    _sample_sp_config,
)

SID = "saml-idp-sid"


@pytest.fixture
def session_data(mocker, test_user) -> dict:
    data = {
        "user_id": str(test_user["id"]),
        "session_start": int(time.time()),
        SESSION_ID_KEY: SID,
        "_csrf_token": "csrf",
    }
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


@pytest.fixture
def http(client, test_tenant_host):
    class _Client:
        def get(self, url, **kw):
            return client.get(url, headers={"Host": test_tenant_host}, follow_redirects=False, **kw)

        def post(self, url, **kw):
            return client.post(
                url, headers={"Host": test_tenant_host}, follow_redirects=False, **kw
            )

    return _Client()


def _revoke(test_tenant, sid=SID):
    tid = str(test_tenant["id"])
    database.revoked_sessions.revoke_session(tid, tid, sid)


def _revoked(test_tenant, sid=SID) -> bool:
    return database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), sid)


class TestSsoRequest:
    def _sso(self, http):
        with patch(
            "services.service_providers.get_sp_by_entity_id", return_value=_sample_sp_config()
        ):
            return http.get(
                "/saml/idp/sso",
                params={"SAMLRequest": _encode_redirect(_make_authn_request_xml())},
            )

    def test_live_session_goes_to_consent(self, http, session_data):
        response = self._sso(http)
        assert response.headers["location"] == "/saml/idp/consent"
        assert session_data["pending_sso_user_id"] == session_data["user_id"]

    def test_revoked_session_logs_in_again_keeping_the_request(
        self, http, session_data, test_tenant
    ):
        _revoke(test_tenant)
        response = self._sso(http)
        assert response.headers["location"] == "/login"
        assert "user_id" not in session_data
        assert "pending_sso_user_id" not in session_data
        # The AuthnRequest survives, so login resumes it.
        assert all(key in session_data for key in PENDING_SSO_KEYS)

    def test_deactivated_user_cannot_use_the_session(
        self, http, session_data, test_tenant, test_user
    ):
        database.users.inactivate_user(test_tenant["id"], test_user["id"])
        assert self._sso(http).headers["location"] == "/login"


class TestConsent:
    def test_revoked_session_gets_no_session_error(self, http, session_data, test_tenant):
        session_data.update(
            {
                "pending_sso_sp_id": "sp",
                "pending_sso_sp_entity_id": "https://sp.example.com",
                "pending_sso_user_id": session_data["user_id"],
            }
        )
        _revoke(test_tenant)
        page = http.get("/saml/idp/consent")
        assert page.status_code == 400
        assert "user_id" not in session_data

    def test_revoked_session_cannot_post_consent(self, http, session_data, test_tenant):
        _revoke(test_tenant)
        response = http.post("/saml/idp/consent", data={"action": "continue", "csrf_token": "csrf"})
        assert response.status_code == 400

    def test_revoked_session_cannot_launch(self, http, session_data, test_tenant):
        _revoke(test_tenant)
        response = http.get("/saml/idp/launch/00000000-0000-0000-0000-000000000000")
        assert response.headers["location"] == "/login"


class TestSignOutsRevoke:
    def test_switch_account_revokes_and_audits(self, http, session_data, test_tenant):
        response = http.post("/saml/idp/consent/switch-account", data={"csrf_token": "csrf"})
        assert response.headers["location"] == "/login"
        assert _revoked(test_tenant)
        event = next(
            e
            for e in database.event_log.list_events(test_tenant["id"], limit=10)
            if e["event_type"] == "user_signed_out"
        )
        assert event["metadata"]["reason"] == "sso_switch_account"
        assert event["metadata"]["refresh_tokens_revoked"] == 0
        assert event["metadata"]["backchannel_logout_count"] == 0

    def test_sp_initiated_slo_revokes(self, http, session_data, test_tenant):
        from tests.routers.test_saml_idp_slo import _encode_redirect as slo_encode
        from tests.routers.test_saml_idp_slo import _make_logout_request_xml

        with patch(
            "services.service_providers.slo.process_sp_logout_request",
            return_value=("base64-logout-response", "https://sp.example.com/slo"),
        ):
            response = http.get(
                "/saml/idp/slo", params={"SAMLRequest": slo_encode(_make_logout_request_xml())}
            )
        assert response.status_code == 200
        assert _revoked(test_tenant)
        assert "user_id" not in session_data

    def test_rejected_slo_request_revokes_nothing(self, http, session_data, test_tenant):
        from tests.routers.test_saml_idp_slo import _encode_redirect as slo_encode
        from tests.routers.test_saml_idp_slo import _make_logout_request_xml

        with patch(
            "services.service_providers.slo.process_sp_logout_request",
            side_effect=ValueError("unknown SP"),
        ):
            http.get(
                "/saml/idp/slo", params={"SAMLRequest": slo_encode(_make_logout_request_xml())}
            )
        assert not _revoked(test_tenant)
        assert session_data["user_id"]
