"""Tests for OIDC upstream back-channel logout (WeftID as the RP).

``validate_logout_token`` is covered claim by claim with tokens signed by the
recorded fixture key (JWKS fetch patched). ``handle_backchannel_logout`` and
``record_upstream_session`` run against the real database: sessions linked at
sign-in are revoked, their links consumed, audit written, replays refused.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import database
import jwt
import pytest
from services import sessions as sessions_service
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream import logout as logout_service
from services.oidc_upstream.errors import LogoutTokenError

from tests.fixtures.oidc import load_fixture, load_fixture_text

JWKS_DOC = load_fixture("jwks")
PRIVATE_KEY_PEM = load_fixture_text("private_key.pem")
KID = "oidc-upstream-fixture-key"
ISSUER = "https://idp.example.com"
CLIENT_ID = "weftid-at-idp"
JWKS_URI = "https://idp.example.com/jwks"
TENANT_ISSUER = "https://tenant.example.com"
EVENT = logout_service.BACKCHANNEL_LOGOUT_EVENT


@pytest.fixture(autouse=True)
def fresh_jwks_state():
    logout_service._last_refetch.clear()
    yield
    logout_service._last_refetch.clear()


@pytest.fixture
def fetch_jwks():
    with patch("services.oidc_upstream.jwks._fetch_jwks", return_value=JWKS_DOC) as fetch:
        yield fetch


def _payload(**overrides):
    now = datetime.now(UTC)
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=2)).timestamp()),
        "jti": uuid4().hex,
        "events": {EVENT: {}},
        "sub": "up-sub",
        "sid": "up-sid",
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def _sign(payload, *, headers=None, key=PRIVATE_KEY_PEM):
    return jwt.encode(
        payload,
        key,
        algorithm="RS256",
        headers={"kid": KID, "typ": "logout+jwt", **(headers or {})},
    )


def _validate(token, connection_id="c1"):
    return logout_service.validate_logout_token(
        token=token,
        tenant_id="t1",
        connection_id=connection_id,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        jwks_uri=JWKS_URI,
    )


def _other_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return other.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


class TestValidateLogoutToken:
    @pytest.fixture(autouse=True)
    def _jwks(self, fetch_jwks):
        jwks_service.clear_jwks_cache("t1", "c1")
        yield

    def test_valid_token(self):
        claims = _validate(_sign(_payload()))
        assert claims["sid"] == "up-sid"
        assert claims["sub"] == "up-sub"

    @pytest.mark.parametrize("typ", ["logout+jwt", "application/logout+jwt", "JWT"])
    def test_accepted_typ(self, typ):
        _validate(_sign(_payload(), headers={"typ": typ}))

    def test_no_typ_accepted(self):
        token = jwt.encode(_payload(), PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": KID})
        assert jwt.get_unverified_header(token).get("typ") in (None, "JWT")
        _validate(token)

    def test_wrong_typ(self):
        with pytest.raises(LogoutTokenError) as exc:
            _validate(_sign(_payload(), headers={"typ": "at+jwt"}))
        assert exc.value.reason == "typ"

    def test_sid_only(self):
        assert _validate(_sign(_payload(sub=None)))["sid"] == "up-sid"

    def test_sub_only(self):
        assert _validate(_sign(_payload(sid=None)))["sub"] == "up-sub"

    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            ({"iss": "https://evil.example.com"}, "issuer"),
            ({"aud": "someone-else"}, "audience"),
            ({"exp": int((datetime.now(UTC) - timedelta(minutes=5)).timestamp())}, "expired"),
            ({"iat": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())}, "not_yet_valid"),
            ({"exp": None}, "missing_claim"),
            ({"iat": None}, "missing_claim"),
            ({"jti": None}, "missing_claim"),
            ({"sid": None, "sub": None}, "missing_claim"),
            ({"events": None}, "events"),
            ({"events": {"http://example.com/other": {}}}, "events"),
            ({"events": {EVENT: "yes"}}, "events"),
            ({"nonce": "n"}, "nonce"),
            ({"sid": 42}, "sid"),
            ({"sub": 42}, "sub"),
            ({"jti": 42}, "jti"),
            ({"jti": ""}, "jti"),
        ],
    )
    def test_rejected_claims(self, overrides, reason):
        with pytest.raises(LogoutTokenError) as exc:
            _validate(_sign(_payload(**overrides)))
        assert exc.value.reason == reason

    def test_not_a_jwt(self):
        with pytest.raises(LogoutTokenError) as exc:
            _validate("not-a-jwt")
        assert exc.value.reason == "malformed"

    def test_missing_kid_with_foreign_key_rejected(self):
        """Without a kid the JWKS's only key is used; a token signed by any
        other key still fails (the kid-less path is not a bypass)."""
        token = jwt.encode(_payload(), _other_key_pem(), algorithm="RS256")
        with pytest.raises(LogoutTokenError) as exc:
            _validate(token)
        assert exc.value.reason == "signature"

    def test_missing_kid_single_key_accepted(self):
        token = jwt.encode(_payload(), PRIVATE_KEY_PEM, algorithm="RS256")
        _validate(token)

    def test_hs256_rejected(self):
        token = jwt.encode(_payload(), "s" * 32, algorithm="HS256", headers={"kid": KID})
        with pytest.raises(LogoutTokenError) as exc:
            _validate(token)
        assert exc.value.reason == "algorithm"

    def test_foreign_key_rejected(self):
        with pytest.raises(LogoutTokenError) as exc:
            _validate(_sign(_payload(), key=_other_key_pem()))
        assert exc.value.reason == "signature"

    def test_jwks_failure(self, fetch_jwks):
        jwks_service.clear_jwks_cache("t1", "c1")
        fetch_jwks.side_effect = jwks_service.JwksError("down")
        with pytest.raises(LogoutTokenError) as exc:
            _validate(_sign(_payload()))
        assert exc.value.reason == "jwks"


class TestJwksRefetchThrottle:
    def test_signature_failure_refetches_once_per_interval(self, fetch_jwks):
        jwks_service.clear_jwks_cache("t1", "c-throttle")
        bad = _sign(_payload(), key=_other_key_pem())
        for _ in range(3):
            with pytest.raises(LogoutTokenError):
                _validate(bad, connection_id="c-throttle")
        # Initial fetch plus exactly one refetch, however many forged tokens.
        assert fetch_jwks.call_count == 2

    def test_rotated_key_picked_up_by_refetch(self, fetch_jwks):
        jwks_service.clear_jwks_cache("t1", "c-rotate")
        stale = {"keys": [{**JWKS_DOC["keys"][0], "kid": "retired-key"}]}
        fetch_jwks.side_effect = [stale, JWKS_DOC]
        assert _validate(_sign(_payload()), connection_id="c-rotate")["sid"] == "up-sid"

    def test_non_signature_failure_does_not_refetch(self, fetch_jwks):
        jwks_service.clear_jwks_cache("t1", "c-iss")
        with pytest.raises(LogoutTokenError):
            _validate(_sign(_payload(iss="https://evil.example.com")), connection_id="c-iss")
        assert fetch_jwks.call_count == 1


# ---------------------------------------------------------------------------
# Real database
# ---------------------------------------------------------------------------


@pytest.fixture
def connection(test_tenant, test_admin_user):
    row = database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"IdP {uuid4().hex[:6]}",
        provider_type="generic",
        issuer=ISSUER,
        created_by=str(test_admin_user["id"]),
        client_id=CLIENT_ID,
        jwks_uri=JWKS_URI,
    )
    yield row
    jwks_service.clear_jwks_cache(str(test_tenant["id"]), str(row["id"]))


def _record(test_tenant, connection, user, sid, *, sub="up-sub", upstream_sid="up-sid"):
    assert logout_service.record_upstream_session(
        tenant_id=str(test_tenant["id"]),
        sid=sid,
        connection_id=str(connection["id"]),
        user_id=str(user["id"]),
        upstream_sub=sub,
        upstream_sid=upstream_sid,
    )


def _handle(test_tenant, connection, token):
    return logout_service.handle_backchannel_logout(
        tenant_id=str(test_tenant["id"]),
        connection_id=str(connection["id"]),
        logout_token=token,
        issuer=TENANT_ISSUER,
    )


def _revoked(test_tenant, sid) -> bool:
    return database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), sid)


def _events(test_tenant, event_type) -> list[dict]:
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=50)
        if e["event_type"] == event_type
    ]


class TestRecordUpstreamSession:
    def test_records_link(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1")
        row = database.oidc_upstream.get_idp_session(str(test_tenant["id"]), "w1")
        assert row["upstream_sid"] == "up-sid"

    @pytest.mark.parametrize(("sub", "sid"), [("x" * 256, None), ("s", "x" * 256)])
    def test_overlong_identifiers_not_recorded(self, test_tenant, connection, test_user, sub, sid):
        assert not logout_service.record_upstream_session(
            tenant_id=str(test_tenant["id"]),
            sid="w1",
            connection_id=str(connection["id"]),
            user_id=str(test_user["id"]),
            upstream_sub=sub,
            upstream_sid=sid,
        )
        assert database.oidc_upstream.get_idp_session(str(test_tenant["id"]), "w1") is None


class TestHandleBackchannelLogout:
    @pytest.fixture(autouse=True)
    def _jwks(self, fetch_jwks):
        yield

    def test_sid_ends_linked_sessions_only(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1", upstream_sid="up-sid")
        _record(test_tenant, connection, test_user, "w2", upstream_sid="other-sid")

        result = _handle(test_tenant, connection, _sign(_payload()))

        assert result.sessions_ended == 1
        assert result.matched_by == "sid"
        assert _revoked(test_tenant, "w1")
        assert not _revoked(test_tenant, "w2")
        assert database.oidc_upstream.get_idp_session(str(test_tenant["id"]), "w1") is None
        assert database.oidc_upstream.get_idp_session(str(test_tenant["id"]), "w2") is not None

    def test_sub_only_ends_every_session_of_subject(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1", upstream_sid="a")
        _record(test_tenant, connection, test_user, "w2", upstream_sid=None)
        _record(test_tenant, connection, test_user, "w3", sub="someone-else")

        result = _handle(test_tenant, connection, _sign(_payload(sid=None)))

        assert result.sessions_ended == 2
        assert result.matched_by == "sub"
        assert _revoked(test_tenant, "w1") and _revoked(test_tenant, "w2")
        assert not _revoked(test_tenant, "w3")

    def test_sid_and_sub_must_both_match(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1", sub="alice", upstream_sid="up-sid")
        result = _handle(test_tenant, connection, _sign(_payload(sub="bob")))
        assert result.sessions_ended == 0
        assert not _revoked(test_tenant, "w1")

    def test_no_matching_session_is_success(self, test_tenant, connection):
        result = _handle(test_tenant, connection, _sign(_payload()))
        assert result.sessions_ended == 0
        assert _events(test_tenant, "user_signed_out") == []

    def test_audits_each_ended_session(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1")
        _handle(test_tenant, connection, _sign(_payload()))
        (event,) = _events(test_tenant, "user_signed_out")
        assert str(event["actor_user_id"]) == str(test_user["id"])
        assert str(event["artifact_id"]) == str(test_user["id"])
        assert event["metadata"]["reason"] == "upstream_backchannel_logout"
        assert event["metadata"]["idp_id"] == str(connection["id"])
        assert event["metadata"]["matched_by"] == "sid"
        assert event["metadata"]["refresh_tokens_revoked"] == 0
        assert event["metadata"]["backchannel_logout_count"] == 0

    def test_downstream_fanout_runs(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1")
        with patch.object(
            logout_service, "end_oidc_session", wraps=logout_service.end_oidc_session
        ) as end:
            _handle(test_tenant, connection, _sign(_payload()))
        end.assert_called_once_with(
            tenant_id=str(test_tenant["id"]), issuer=TENANT_ISSUER, sid="w1"
        )

    def test_replay_rejected_and_audited(self, test_tenant, connection, test_user):
        token = _sign(_payload())
        _handle(test_tenant, connection, token)
        _record(test_tenant, connection, test_user, "w1")

        with pytest.raises(LogoutTokenError) as exc:
            _handle(test_tenant, connection, token)

        assert exc.value.reason == "replay"
        assert not _revoked(test_tenant, "w1")
        (event,) = _events(test_tenant, "oidc_idp_logout_rejected")
        assert event["metadata"]["reason"] == "replay"
        assert str(event["artifact_id"]) == str(connection["id"])

    def test_invalid_token_audited(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1")
        with pytest.raises(LogoutTokenError):
            _handle(test_tenant, connection, _sign(_payload(aud="other")))
        assert not _revoked(test_tenant, "w1")
        (event,) = _events(test_tenant, "oidc_idp_logout_rejected")
        assert event["metadata"]["reason"] == "audience"
        assert event["metadata"]["idp_name"] == connection["name"]

    def test_overlong_jti_rejected(self, test_tenant, connection):
        with pytest.raises(LogoutTokenError) as exc:
            _handle(test_tenant, connection, _sign(_payload(jti="j" * 256)))
        assert exc.value.reason == "replay"

    def test_unknown_connection_not_audited(self, test_tenant):
        with pytest.raises(LogoutTokenError) as exc:
            logout_service.handle_backchannel_logout(
                tenant_id=str(test_tenant["id"]),
                connection_id=str(uuid4()),
                logout_token=_sign(_payload()),
                issuer=TENANT_ISSUER,
            )
        assert exc.value.reason == "unknown_connection"
        assert _events(test_tenant, "oidc_idp_logout_rejected") == []

    def test_unconfigured_connection_rejected(self, test_tenant, connection):
        database.oidc_upstream.update_connection(
            test_tenant["id"], str(connection["id"]), jwks_uri=None
        )
        with pytest.raises(LogoutTokenError) as exc:
            _handle(test_tenant, connection, _sign(_payload()))
        assert exc.value.reason == "configuration_error"
        assert _events(test_tenant, "oidc_idp_logout_rejected")

    def test_other_tenant_connection_not_found(self, test_tenant, connection):
        suffix = uuid4().hex[:8]
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, :n) returning id",
            {"s": f"other-{suffix}", "n": suffix},
        )
        try:
            with pytest.raises(LogoutTokenError) as exc:
                logout_service.handle_backchannel_logout(
                    tenant_id=str(other["id"]),
                    connection_id=str(connection["id"]),
                    logout_token=_sign(_payload()),
                    issuer=TENANT_ISSUER,
                )
            assert exc.value.reason == "unknown_connection"
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
            )


class TestSessionsService:
    def test_revoke_session_revokes_and_forgets_link(self, test_tenant, connection, test_user):
        _record(test_tenant, connection, test_user, "w1")
        sessions_service.revoke_session(tenant_id=str(test_tenant["id"]), sid="w1")
        assert _revoked(test_tenant, "w1")
        assert database.oidc_upstream.get_idp_session(str(test_tenant["id"]), "w1") is None

    def test_cleanup_session_state_uses_retention_constants(self):
        with (
            patch.object(
                database.revoked_sessions, "purge_revoked_sessions", return_value=1
            ) as purge,
            patch.object(
                database.oidc_upstream, "sweep_stale_idp_sessions", return_value=2
            ) as sweep,
            patch.object(database.oidc_upstream, "purge_expired_logout_token_jtis", return_value=3),
        ):
            assert sessions_service.cleanup_session_state() == {
                "revoked_sessions_purged": 1,
                "upstream_sessions_swept": 2,
                "logout_token_jtis_purged": 3,
            }
        purge.assert_called_once_with(older_than_days=15)
        sweep.assert_called_once_with(older_than_days=90)
