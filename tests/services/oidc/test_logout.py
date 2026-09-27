"""Tests for end_session request resolution (services/oidc/logout.py).

Real database, real tenant signing keys: hints are minted by the ID-token
service and verified the way the endpoint does.
"""

import database
import jwt
import pytest
from services.oidc import logout as logout_service
from services.oidc import tokens as tokens_service

ISSUER = "https://tenant.example.com"
BYE = "https://rp.example/bye"


@pytest.fixture
def rp_client(test_tenant, test_admin_user):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Logout RP",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        post_logout_redirect_uris=[BYE],
    )


def _hint(test_tenant, user, client, *, issuer=ISSUER, sid=None) -> str:
    return tokens_service.issue_id_token(
        tenant_id=str(test_tenant["id"]),
        issuer=issuer,
        client_uuid=str(client["id"]),
        client_id=client["client_id"],
        user_id=str(user["id"]),
        scopes={"openid"},
        sid=sid,
    )


def _resolve(test_tenant, **kw):
    params = {"id_token_hint": None, "client_id": None, "post_logout_redirect_uri": None}
    params.update(kw)
    return logout_service.resolve_end_session_request(
        tenant_id=str(test_tenant["id"]), issuer=ISSUER, **params
    )


class TestVerifiedHint:
    def test_hint_with_registered_uri_is_fully_verified(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            post_logout_redirect_uri=BYE,
        )
        assert resolved.problem is None
        assert resolved.hint_subject == str(test_user["id"])
        assert resolved.client["client_id"] == rp_client["client_id"]
        assert resolved.post_logout_redirect_uri == BYE

    def test_hint_alone_names_the_client_by_audience(self, test_tenant, test_user, rp_client):
        resolved = _resolve(test_tenant, id_token_hint=_hint(test_tenant, test_user, rp_client))
        assert resolved.problem is None
        assert resolved.client["client_id"] == rp_client["client_id"]
        assert resolved.post_logout_redirect_uri is None

    def test_matching_client_id_is_accepted(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            client_id=rp_client["client_id"],
            post_logout_redirect_uri=BYE,
        )
        assert resolved.problem is None and resolved.post_logout_redirect_uri == BYE

    def test_expired_hint_still_verifies(self, test_tenant, test_user, rp_client, mocker):
        from datetime import timedelta

        mocker.patch.object(tokens_service, "ID_TOKEN_EXPIRY", timedelta(hours=-1))
        resolved = _resolve(test_tenant, id_token_hint=_hint(test_tenant, test_user, rp_client))
        assert resolved.problem is None and resolved.hint_subject == str(test_user["id"])


class TestHintAudiencePeek:
    """The unverified audience peek only picks which client to verify against."""

    def _unsigned(self, claims: dict) -> str:
        return jwt.encode(claims, key=None, algorithm="none")

    def test_string_audience(self):
        assert logout_service._hint_audience(self._unsigned({"aud": "rp-1"})) == "rp-1"

    def test_one_element_list(self):
        assert logout_service._hint_audience(self._unsigned({"aud": ["rp-1"]})) == "rp-1"

    def test_ambiguous_or_missing_audience(self):
        for claims in ({"aud": ["rp-1", "rp-2"]}, {"aud": ""}, {"aud": 5}, {}):
            assert logout_service._hint_audience(self._unsigned(claims)) is None

    def test_not_a_jwt(self):
        assert logout_service._hint_audience("garbage") is None


class TestRejectedHint:
    def test_garbage_hint(self, test_tenant, rp_client):
        resolved = _resolve(test_tenant, id_token_hint="not-a-jwt", post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT
        assert resolved.post_logout_redirect_uri is None
        assert resolved.client is None

    def test_alg_none_hint(self, test_tenant, test_user, rp_client):
        token = _hint(test_tenant, test_user, rp_client)
        claims = jwt.decode(token, options={"verify_signature": False})
        unsigned = jwt.encode(claims, key=None, algorithm="none")
        resolved = _resolve(test_tenant, id_token_hint=unsigned, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_signed_by_another_key(self, test_tenant, test_user, rp_client):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        real = jwt.get_unverified_header(_hint(test_tenant, test_user, rp_client))
        forged = jwt.encode(
            {"iss": ISSUER, "sub": str(test_user["id"]), "aud": rp_client["client_id"]},
            pem,
            algorithm="RS256",
            headers={"kid": real["kid"]},
        )
        resolved = _resolve(test_tenant, id_token_hint=forged, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_for_another_issuer(self, test_tenant, test_user, rp_client):
        token = _hint(test_tenant, test_user, rp_client, issuer="https://other.example.com")
        resolved = _resolve(test_tenant, id_token_hint=token)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_client_id_disagreeing_with_hint(
        self, test_tenant, test_user, rp_client, normal_oauth2_client
    ):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            client_id=normal_oauth2_client["client_id"],
        )
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_for_deactivated_client(self, test_tenant, test_user, rp_client):
        token = _hint(test_tenant, test_user, rp_client)
        database.oauth2.deactivate_client(test_tenant["id"], rp_client["client_id"])
        resolved = _resolve(test_tenant, id_token_hint=token, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT

    def test_hint_for_unknown_audience(self, test_tenant, test_user, rp_client):
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=ISSUER,
            client_uuid=str(rp_client["id"]),
            client_id="no-such-client",
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        resolved = _resolve(test_tenant, id_token_hint=token)
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT


class TestRedirectTarget:
    def test_unregistered_uri(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            post_logout_redirect_uri="https://evil.example/bye",
        )
        assert resolved.problem == logout_service.PROBLEM_UNREGISTERED_POST_LOGOUT_REDIRECT_URI
        assert resolved.post_logout_redirect_uri is None
        assert resolved.hint_subject == str(test_user["id"])

    def test_query_added_to_registered_uri_is_unregistered(self, test_tenant, test_user, rp_client):
        resolved = _resolve(
            test_tenant,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            post_logout_redirect_uri=BYE + "?foo=bar",
        )
        assert resolved.problem == logout_service.PROBLEM_UNREGISTERED_POST_LOGOUT_REDIRECT_URI

    def test_uri_without_hint_is_never_honoured(self, test_tenant, rp_client):
        """client_id + a registered URI is not enough: anyone can build that link."""
        resolved = _resolve(
            test_tenant, client_id=rp_client["client_id"], post_logout_redirect_uri=BYE
        )
        assert resolved.problem == logout_service.PROBLEM_ID_TOKEN_HINT_REQUIRED
        assert resolved.post_logout_redirect_uri is None
        assert resolved.client["client_id"] == rp_client["client_id"]

    def test_uri_alone(self, test_tenant, rp_client):
        resolved = _resolve(test_tenant, post_logout_redirect_uri=BYE)
        assert resolved.problem == logout_service.PROBLEM_ID_TOKEN_HINT_REQUIRED
        assert resolved.client is None


class TestNoHint:
    def test_no_parameters(self, test_tenant):
        resolved = _resolve(test_tenant)
        assert resolved == logout_service.EndSessionRequest()
        assert resolved.hint_subject is None

    def test_known_client_id_alone(self, test_tenant, rp_client):
        resolved = _resolve(test_tenant, client_id=rp_client["client_id"])
        assert resolved.problem is None
        assert resolved.hint_claims is None
        assert resolved.client["client_id"] == rp_client["client_id"]

    def test_unknown_client_id(self, test_tenant):
        resolved = _resolve(test_tenant, client_id="no-such-client")
        assert resolved.problem == logout_service.PROBLEM_UNKNOWN_CLIENT

    def test_b2b_client_id_is_unknown(self, test_tenant, b2b_oauth2_client):
        resolved = _resolve(test_tenant, client_id=b2b_oauth2_client["client_id"])
        assert resolved.problem == logout_service.PROBLEM_UNKNOWN_CLIENT


def test_other_tenant_client_is_unknown(test_tenant, test_user, rp_client):
    """Resolution is tenant-scoped: another tenant never sees this client."""
    import uuid

    other = database.fetchone(
        database.UNSCOPED,
        "insert into tenants (subdomain, name) values (:s, 'Other') returning id",
        {"s": f"other-{uuid.uuid4().hex[:8]}"},
    )
    try:
        resolved = logout_service.resolve_end_session_request(
            tenant_id=str(other["id"]),
            issuer=ISSUER,
            id_token_hint=_hint(test_tenant, test_user, rp_client),
            client_id=None,
            post_logout_redirect_uri=BYE,
        )
        assert resolved.problem == logout_service.PROBLEM_INVALID_ID_TOKEN_HINT
    finally:
        database.execute(
            database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
        )


# ---------------------------------------------------------------------------
# end_oidc_session (Front-Channel Logout 1.0)
# ---------------------------------------------------------------------------

FC_URI = "https://rp.example/fc-logout"


def _fc_client(test_tenant, test_admin_user, name, *, uri=FC_URI, session_required=True):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name=name,
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        frontchannel_logout_uri=uri,
        frontchannel_logout_session_required=session_required,
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True
    )
    return client


def _end_session(test_tenant, sid, **kw):
    return logout_service.end_oidc_session(
        tenant_id=str(test_tenant["id"]), issuer=ISSUER, sid=sid, **kw
    )


def _end(test_tenant, sid, **kw):
    """The front-channel URLs of ending the session."""
    return _end_session(test_tenant, sid, **kw).frontchannel_logout_urls


class TestEndOidcSession:
    def test_session_required_url_carries_iss_and_sid(
        self, test_tenant, test_user, test_admin_user
    ):
        client = _fc_client(test_tenant, test_admin_user, "FC")
        _hint(test_tenant, test_user, client, sid="s-1")

        assert _end(test_tenant, "s-1") == [
            "https://rp.example/fc-logout?iss=https%3A%2F%2Ftenant.example.com&sid=s-1"
        ]

    def test_url_without_session_required_is_sent_as_registered(
        self, test_tenant, test_user, test_admin_user
    ):
        client = _fc_client(test_tenant, test_admin_user, "FC", session_required=False)
        _hint(test_tenant, test_user, client, sid="s-1")

        assert _end(test_tenant, "s-1") == [FC_URI]

    def test_parameters_join_a_registered_query(self, test_tenant, test_user, test_admin_user):
        client = _fc_client(test_tenant, test_admin_user, "FC", uri=f"{FC_URI}?app=1")
        _hint(test_tenant, test_user, client, sid="s-1")

        (url,) = _end(test_tenant, "s-1")
        assert url.startswith(f"{FC_URI}?app=1&iss=") and url.endswith("&sid=s-1")

    def test_records_are_consumed(self, test_tenant, test_user, test_admin_user):
        """A session ends once: a second call finds nothing."""
        client = _fc_client(test_tenant, test_admin_user, "FC")
        _hint(test_tenant, test_user, client, sid="s-1")

        assert len(_end(test_tenant, "s-1")) == 1
        assert _end(test_tenant, "s-1") == []

    def test_only_the_ending_session_is_touched(self, test_tenant, test_user, test_admin_user):
        client = _fc_client(test_tenant, test_admin_user, "FC")
        _hint(test_tenant, test_user, client, sid="s-1")
        _hint(test_tenant, test_user, client, sid="s-2")

        assert _end(test_tenant, "s-1") != []
        assert _end(test_tenant, "s-2") != []

    def test_several_clients_in_first_issued_order(self, test_tenant, test_user, test_admin_user):
        first = _fc_client(test_tenant, test_admin_user, "First", uri="https://rp.example/a")
        second = _fc_client(test_tenant, test_admin_user, "Second", uri="https://rp.example/b")
        _hint(test_tenant, test_user, first, sid="s-1")
        _hint(test_tenant, test_user, second, sid="s-1")

        urls = _end(test_tenant, "s-1")
        assert [u.split("?")[0] for u in urls] == ["https://rp.example/a", "https://rp.example/b"]

    def test_identical_urls_are_loaded_once(self, test_tenant, test_user, test_admin_user):
        first = _fc_client(test_tenant, test_admin_user, "First", session_required=False)
        second = _fc_client(test_tenant, test_admin_user, "Second", session_required=False)
        _hint(test_tenant, test_user, first, sid="s-1")
        _hint(test_tenant, test_user, second, sid="s-1")

        assert _end(test_tenant, "s-1") == [FC_URI]

    def test_clients_that_are_not_notified(self, test_tenant, test_user, test_admin_user):
        """No URI, deactivated, or OIDC switched off: record removed, no iframe."""
        no_uri = _fc_client(test_tenant, test_admin_user, "No URI", uri=None)
        inactive = _fc_client(test_tenant, test_admin_user, "Inactive")
        database.oauth2.deactivate_client(test_tenant["id"], inactive["client_id"])
        not_oidc = _fc_client(test_tenant, test_admin_user, "Not OIDC")
        database.oauth2.update_client_oidc_settings(
            test_tenant["id"], not_oidc["client_id"], oidc_enabled=False
        )
        for client in (no_uri, inactive, not_oidc):
            _hint(test_tenant, test_user, client, sid="s-1")

        assert _end(test_tenant, "s-1") == []
        rows = database.fetchall(str(test_tenant["id"]), "select 1 from oidc_session_clients")
        assert rows == []

    def test_excluded_client_is_not_notified_but_forgotten(
        self, test_tenant, test_user, test_admin_user
    ):
        asking = _fc_client(test_tenant, test_admin_user, "Asking", uri="https://rp.example/a")
        other = _fc_client(test_tenant, test_admin_user, "Other", uri="https://rp.example/b")
        _hint(test_tenant, test_user, asking, sid="s-1")
        _hint(test_tenant, test_user, other, sid="s-1")

        urls = _end(test_tenant, "s-1", exclude_client_uuid=str(asking["id"]))
        assert [u.split("?")[0] for u in urls] == ["https://rp.example/b"]
        assert _end(test_tenant, "s-1") == []

    @pytest.mark.parametrize("sid", [None, ""])
    def test_no_session_identifier(self, test_tenant, sid):
        assert _end(test_tenant, sid) == []

    def test_unknown_session(self, test_tenant):
        assert _end(test_tenant, "never-issued") == []

    def test_session_is_revoked_server_side(self, test_tenant):
        _end(test_tenant, "s-revoke")
        assert database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), "s-revoke")
        assert not database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), "s-other")

    @pytest.mark.parametrize("sid", [None, ""])
    def test_no_session_identifier_revokes_nothing(self, test_tenant, sid, mocker):
        revoke = mocker.patch.object(logout_service, "revoke_session")
        _end(test_tenant, sid)
        revoke.assert_not_called()

    def test_other_tenant_cannot_consume_the_session(self, test_tenant, test_user, test_admin_user):
        import uuid

        client = _fc_client(test_tenant, test_admin_user, "FC")
        _hint(test_tenant, test_user, client, sid="s-1")
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, 'Other') returning id",
            {"s": f"other-{uuid.uuid4().hex[:8]}"},
        )
        try:
            ended = logout_service.end_oidc_session(
                tenant_id=str(other["id"]), issuer=ISSUER, sid="s-1"
            )
            assert ended.frontchannel_logout_urls == []
            assert ended.backchannel_logout_count == 0
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
            )
        assert len(_end(test_tenant, "s-1")) == 1


# ---------------------------------------------------------------------------
# end_oidc_session: back-channel deliveries queued (Back-Channel Logout 1.0)
# ---------------------------------------------------------------------------

BC_URI = "https://rp.example/bc-logout"


def _bc_client(test_tenant, test_admin_user, name, *, uri=BC_URI, fc_uri=None):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name=name,
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        frontchannel_logout_uri=fc_uri,
        backchannel_logout_uri=uri,
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True
    )
    return client


def _deliveries(test_tenant):
    return database.fetchall(
        str(test_tenant["id"]),
        "select * from oidc_backchannel_logout_deliveries order by created_at",
    )


class TestEndOidcSessionBackchannel:
    def test_delivery_queued_for_back_channel_client(self, test_tenant, test_user, test_admin_user):
        client = _bc_client(test_tenant, test_admin_user, "BC")
        _hint(test_tenant, test_user, client, sid="s-1")

        ended = _end_session(test_tenant, "s-1")

        assert ended.backchannel_logout_count == 1
        assert ended.frontchannel_logout_urls == []
        (row,) = _deliveries(test_tenant)
        assert str(row["client_id"]) == str(client["id"])
        assert row["sub"] == str(test_user["id"])
        assert row["sid"] == "s-1"
        assert row["issuer"] == ISSUER
        assert row["status"] == "pending"
        assert row["attempts"] == 0

    def test_client_with_both_channels_gets_both(self, test_tenant, test_user, test_admin_user):
        client = _bc_client(test_tenant, test_admin_user, "Both", fc_uri=FC_URI)
        _hint(test_tenant, test_user, client, sid="s-1")

        ended = _end_session(test_tenant, "s-1")

        assert len(ended.frontchannel_logout_urls) == 1
        assert ended.backchannel_logout_count == 1

    def test_one_delivery_per_client(self, test_tenant, test_user, test_admin_user):
        first = _bc_client(test_tenant, test_admin_user, "First")
        second = _bc_client(test_tenant, test_admin_user, "Second")
        for client in (first, second, first):
            _hint(test_tenant, test_user, client, sid="s-1")

        assert _end_session(test_tenant, "s-1").backchannel_logout_count == 2
        assert {str(r["client_id"]) for r in _deliveries(test_tenant)} == {
            str(first["id"]),
            str(second["id"]),
        }

    def test_clients_that_are_not_queued(self, test_tenant, test_user, test_admin_user):
        """No URI, deactivated, or OIDC switched off: record removed, nothing queued."""
        no_uri = _bc_client(test_tenant, test_admin_user, "No URI", uri=None)
        inactive = _bc_client(test_tenant, test_admin_user, "Inactive")
        database.oauth2.deactivate_client(test_tenant["id"], inactive["client_id"])
        not_oidc = _bc_client(test_tenant, test_admin_user, "Not OIDC")
        database.oauth2.update_client_oidc_settings(
            test_tenant["id"], not_oidc["client_id"], oidc_enabled=False
        )
        for client in (no_uri, inactive, not_oidc):
            _hint(test_tenant, test_user, client, sid="s-1")

        assert _end_session(test_tenant, "s-1").backchannel_logout_count == 0
        assert _deliveries(test_tenant) == []
        rows = database.fetchall(str(test_tenant["id"]), "select 1 from oidc_session_clients")
        assert rows == []

    def test_excluded_client_is_not_queued(self, test_tenant, test_user, test_admin_user):
        asking = _bc_client(test_tenant, test_admin_user, "Asking")
        other = _bc_client(test_tenant, test_admin_user, "Other")
        _hint(test_tenant, test_user, asking, sid="s-1")
        _hint(test_tenant, test_user, other, sid="s-1")

        ended = _end_session(test_tenant, "s-1", exclude_client_uuid=str(asking["id"]))

        assert ended.backchannel_logout_count == 1
        (row,) = _deliveries(test_tenant)
        assert str(row["client_id"]) == str(other["id"])

    def test_session_ends_once(self, test_tenant, test_user, test_admin_user):
        client = _bc_client(test_tenant, test_admin_user, "BC")
        _hint(test_tenant, test_user, client, sid="s-1")

        assert _end_session(test_tenant, "s-1").backchannel_logout_count == 1
        assert _end_session(test_tenant, "s-1").backchannel_logout_count == 0
        assert len(_deliveries(test_tenant)) == 1


# ---------------------------------------------------------------------------
# end_oidc_session: the session's refresh tokens are revoked (BCL 2.7)
# ---------------------------------------------------------------------------


def _session_refresh_token(test_tenant, client, user, sid):
    tid = str(test_tenant["id"])
    token, token_id = database.oauth2.create_refresh_token(
        tid, tid, str(client["id"]), str(user["id"]), scope="openid", sid=sid
    )
    return token


def _refresh_valid(test_tenant, client, token) -> bool:
    return (
        database.oauth2.validate_refresh_token(str(test_tenant["id"]), token, str(client["id"]))
        is not None
    )


class TestEndOidcSessionRefreshTokens:
    def test_session_refresh_tokens_revoked(self, test_tenant, test_user, rp_client):
        mine = _session_refresh_token(test_tenant, rp_client, test_user, "s-1")
        other = _session_refresh_token(test_tenant, rp_client, test_user, "s-2")

        ended = _end_session(test_tenant, "s-1")

        assert ended.refresh_tokens_revoked == 1
        assert not _refresh_valid(test_tenant, rp_client, mine)
        assert _refresh_valid(test_tenant, rp_client, other)

    def test_excluded_client_tokens_revoked_too(self, test_tenant, test_user, rp_client):
        """Re-authentication starts a new session: the old session's tokens go."""
        token = _session_refresh_token(test_tenant, rp_client, test_user, "s-1")
        ended = _end_session(test_tenant, "s-1", exclude_client_uuid=str(rp_client["id"]))
        assert ended.refresh_tokens_revoked == 1
        assert not _refresh_valid(test_tenant, rp_client, token)

    def test_no_sid_revokes_nothing(self, test_tenant, test_user, rp_client):
        token = _session_refresh_token(test_tenant, rp_client, test_user, None)
        ended = logout_service.end_oidc_session(
            tenant_id=str(test_tenant["id"]), issuer=ISSUER, sid=None
        )
        assert ended.refresh_tokens_revoked == 0
        assert _refresh_valid(test_tenant, rp_client, token)


# ---------------------------------------------------------------------------
# end_user_oidc_sessions: deactivation / deletion fan-out
# ---------------------------------------------------------------------------


class TestEndUserOidcSessions:
    def test_every_session_queued(self, test_tenant, test_user, test_admin_user):
        client = _bc_client(test_tenant, test_admin_user, "BC")
        _hint(test_tenant, test_user, client, sid="s-1", issuer="https://recorded.example")
        _hint(test_tenant, test_user, client, sid="s-2", issuer="https://recorded.example")
        _hint(test_tenant, test_admin_user, client, sid="s-3")

        count = logout_service.end_user_oidc_sessions(
            tenant_id=str(test_tenant["id"]), user_id=str(test_user["id"])
        )

        assert count == 2
        rows = _deliveries(test_tenant)
        assert sorted(r["sid"] for r in rows) == ["s-1", "s-2"]
        assert {r["issuer"] for r in rows} == {"https://recorded.example"}
        # The admin's session is untouched and still notifies at its own logout.
        assert _end_session(test_tenant, "s-3").backchannel_logout_count == 1

    def test_unrecorded_issuer_falls_back_to_canonical_host(
        self, test_tenant, test_user, test_admin_user
    ):
        import settings

        client = _bc_client(test_tenant, test_admin_user, "BC")
        tid = str(test_tenant["id"])
        database.oauth2.upsert_session_client(
            tid, tid, sid="old", client_id=str(client["id"]), user_id=str(test_user["id"])
        )

        logout_service.end_user_oidc_sessions(tenant_id=tid, user_id=str(test_user["id"]))

        (row,) = _deliveries(test_tenant)
        assert row["issuer"] == f"https://{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"

    def test_no_sessions(self, test_tenant, test_user):
        assert (
            logout_service.end_user_oidc_sessions(
                tenant_id=str(test_tenant["id"]), user_id=str(test_user["id"])
            )
            == 0
        )


def test_canonical_issuer_without_tenant_or_base_domain(test_tenant, mocker):
    import uuid

    assert logout_service._canonical_issuer(str(uuid.uuid4())) == ""
    mocker.patch.object(logout_service.settings, "BASE_DOMAIN", "")
    assert logout_service._canonical_issuer(str(test_tenant["id"])) == ""
