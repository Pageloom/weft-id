"""Service tests: back-channel logout tokens and their delivery.

The worker entry point ``deliver_due_backchannel_logouts`` is driven with an
``httpx.MockTransport`` client standing in for the relying party.
"""

import json
from urllib.parse import parse_qs

import database
import httpx
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from services import oidc as oidc_service
from services.oidc import backchannel as backchannel_service
from services.oidc import tokens as tokens_service
from utils.request_context import system_context

ISSUER = "https://tenant.example.com"
BC_URI = "https://rp.example/bc"


def _verify(token: str, tenant_id: str, *, audience: str) -> dict:
    header = jwt.get_unverified_header(token)
    jwks = oidc_service.get_jwks(tenant_id)
    entry = next(k for k in jwks.keys if k.kid == header["kid"])
    public_key = RSAAlgorithm.from_jwk(json.dumps(entry.model_dump()))
    return jwt.decode(token, public_key, algorithms=["RS256"], audience=audience, issuer=ISSUER)


@pytest.fixture
def make_client(test_tenant, test_admin_user):
    def _make(name="BC", *, uri=BC_URI, session_required=True):
        client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name=name,
            redirect_uris=["https://rp.example/cb"],
            created_by=test_admin_user["id"],
            backchannel_logout_uri=uri,
            backchannel_logout_session_required=session_required,
        )
        database.oauth2.update_client_oidc_settings(
            test_tenant["id"], client["client_id"], oidc_enabled=True
        )
        return client

    return _make


@pytest.fixture
def queue(test_tenant, test_user):
    """Factory: an ID token for ``client`` in ``sid``, then the session ends."""

    def _queue(client, sid="s-1"):
        tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=ISSUER,
            client_uuid=str(client["id"]),
            client_id=client["client_id"],
            user_id=str(test_user["id"]),
            scopes={"openid"},
            sid=sid,
        )
        oidc_service.end_oidc_session(tenant_id=str(test_tenant["id"]), issuer=ISSUER, sid=sid)

    return _queue


class _RP:
    """A mock relying party: records requests, answers with ``status`` or raises."""

    def __init__(self, status=200, exc: Exception | None = None):
        self.status = status
        self.exc = exc
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.exc is not None:
            raise self.exc
        return httpx.Response(self.status)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    def logout_token(self, index=0) -> str:
        body = parse_qs(self.requests[index].content.decode())
        (token,) = body["logout_token"]
        return token


def _deliver(test_tenant, rp: _RP) -> dict:
    with system_context(), rp.client() as client:
        return backchannel_service.deliver_due_backchannel_logouts(
            str(test_tenant["id"]), http_client=client
        )


def _row(test_tenant) -> dict:
    (row,) = database.fetchall(
        str(test_tenant["id"]), "select * from oidc_backchannel_logout_deliveries"
    )
    return row


def _make_due(test_tenant):
    database.execute(
        str(test_tenant["id"]),
        "update oidc_backchannel_logout_deliveries set next_attempt_at = now()",
    )


def _failed_events(test_tenant) -> list[dict]:
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=50)
        if e["event_type"] == "oidc_backchannel_logout_failed"
    ]


# ---------------------------------------------------------------------------
# The logout token
# ---------------------------------------------------------------------------


class TestLogoutToken:
    def test_claims_and_header(self, test_tenant, test_user):
        token = backchannel_service.build_logout_token(
            tenant_id=str(test_tenant["id"]),
            issuer=ISSUER,
            client_id="client-abc",
            sub=str(test_user["id"]),
            sid="s-1",
        )
        header = jwt.get_unverified_header(token)
        assert header["typ"] == "logout+jwt"
        assert header["alg"] == "RS256"
        assert header["kid"]

        claims = _verify(token, str(test_tenant["id"]), audience="client-abc")
        assert claims["sub"] == str(test_user["id"])
        assert claims["sid"] == "s-1"
        assert claims["events"] == {"http://schemas.openid.net/event/backchannel-logout": {}}
        assert claims["exp"] - claims["iat"] == 120
        assert claims["jti"]
        assert "nonce" not in claims

    def test_sid_omitted_when_not_given(self, test_tenant, test_user):
        token = backchannel_service.build_logout_token(
            tenant_id=str(test_tenant["id"]),
            issuer=ISSUER,
            client_id="client-abc",
            sub=str(test_user["id"]),
            sid=None,
        )
        claims = _verify(token, str(test_tenant["id"]), audience="client-abc")
        assert "sid" not in claims
        assert claims["sub"] == str(test_user["id"])

    def test_every_token_has_a_fresh_jti(self, test_tenant, test_user):
        kw = {
            "tenant_id": str(test_tenant["id"]),
            "issuer": ISSUER,
            "client_id": "client-abc",
            "sub": str(test_user["id"]),
            "sid": "s-1",
        }
        first = jwt.decode(
            backchannel_service.build_logout_token(**kw), options={"verify_signature": False}
        )
        second = jwt.decode(
            backchannel_service.build_logout_token(**kw), options={"verify_signature": False}
        )
        assert first["jti"] != second["jti"]


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


class TestDelivery:
    def test_delivered_on_200(self, test_tenant, test_user, make_client, queue):
        client = make_client()
        queue(client)
        rp = _RP(200)

        counts = _deliver(test_tenant, rp)

        assert counts == {"delivered": 1, "retried": 0, "failed": 0, "skipped": 0}
        (request,) = rp.requests
        assert request.method == "POST"
        assert str(request.url) == BC_URI
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        claims = _verify(rp.logout_token(), str(test_tenant["id"]), audience=client["client_id"])
        assert claims["sub"] == str(test_user["id"])
        assert claims["sid"] == "s-1"
        row = _row(test_tenant)
        assert row["status"] == "delivered"
        assert row["attempts"] == 1
        assert row["last_http_status"] == 200

    def test_delivered_on_204(self, test_tenant, make_client, queue):
        queue(make_client())
        assert _deliver(test_tenant, _RP(204))["delivered"] == 1

    def test_sid_left_out_when_client_does_not_require_it(
        self, test_tenant, test_user, make_client, queue
    ):
        client = make_client(session_required=False)
        queue(client)
        rp = _RP(200)
        _deliver(test_tenant, rp)
        claims = _verify(rp.logout_token(), str(test_tenant["id"]), audience=client["client_id"])
        assert "sid" not in claims
        assert claims["sub"] == str(test_user["id"])

    def test_nothing_due_sends_nothing(self, test_tenant):
        rp = _RP(200)
        assert _deliver(test_tenant, rp) == {
            "delivered": 0,
            "retried": 0,
            "failed": 0,
            "skipped": 0,
        }
        assert rp.requests == []

    def test_delivered_once(self, test_tenant, make_client, queue):
        queue(make_client())
        rp = _RP(200)
        _deliver(test_tenant, rp)
        _deliver(test_tenant, rp)
        assert len(rp.requests) == 1

    @pytest.mark.parametrize("status", [500, 503, 408, 429])
    def test_retryable_status_is_retried(self, test_tenant, make_client, queue, status):
        queue(make_client())

        counts = _deliver(test_tenant, _RP(status))

        assert counts["retried"] == 1
        row = _row(test_tenant)
        assert row["status"] == "pending"
        assert row["attempts"] == 1
        assert row["last_error"] == f"http_{status}"
        assert row["last_http_status"] == status
        delay = (row["next_attempt_at"] - row["last_attempt_at"]).total_seconds()
        assert 29 <= delay <= 31
        assert _failed_events(test_tenant) == []

    def test_network_error_is_retried(self, test_tenant, make_client, queue):
        queue(make_client())

        counts = _deliver(test_tenant, _RP(exc=httpx.ConnectError("refused")))

        assert counts["retried"] == 1
        row = _row(test_tenant)
        assert row["last_error"].startswith("network_error: ConnectError")
        assert row["last_http_status"] is None

    def test_retry_follows_the_schedule(self, test_tenant, make_client, queue):
        queue(make_client())
        rp = _RP(503)
        delays = []
        for _ in backchannel_service.RETRY_SCHEDULE:
            _deliver(test_tenant, rp)
            row = _row(test_tenant)
            delays.append(round((row["next_attempt_at"] - row["last_attempt_at"]).total_seconds()))
            _make_due(test_tenant)
        assert delays == list(backchannel_service.RETRY_SCHEDULE)

    def test_gives_up_after_the_last_attempt(self, test_tenant, make_client, queue):
        client = make_client()
        queue(client)
        rp = _RP(503)
        for _ in range(backchannel_service.MAX_ATTEMPTS - 1):
            assert _deliver(test_tenant, rp)["retried"] == 1
            _make_due(test_tenant)

        counts = _deliver(test_tenant, rp)

        assert counts["failed"] == 1
        assert len(rp.requests) == backchannel_service.MAX_ATTEMPTS
        row = _row(test_tenant)
        assert row["status"] == "failed"
        assert row["attempts"] == backchannel_service.MAX_ATTEMPTS
        (event,) = _failed_events(test_tenant)
        assert str(event["artifact_id"]) == str(client["id"])
        assert event["metadata"]["client_id"] == client["client_id"]
        assert event["metadata"]["attempts"] == backchannel_service.MAX_ATTEMPTS
        assert event["metadata"]["http_status"] == 503

    @pytest.mark.parametrize("status", [400, 401, 404])
    def test_refused_by_rp_fails_at_once(self, test_tenant, make_client, queue, status):
        client = make_client()
        queue(client)

        counts = _deliver(test_tenant, _RP(status))

        assert counts["failed"] == 1
        row = _row(test_tenant)
        assert row["status"] == "failed"
        assert row["attempts"] == 1
        (event,) = _failed_events(test_tenant)
        assert event["metadata"]["error"] == f"http_{status}"

    def test_client_deactivated_since_queueing_is_skipped(self, test_tenant, make_client, queue):
        client = make_client()
        queue(client)
        database.oauth2.deactivate_client(test_tenant["id"], client["client_id"])
        rp = _RP(200)

        counts = _deliver(test_tenant, rp)

        assert counts["skipped"] == 1
        assert rp.requests == []
        row = _row(test_tenant)
        assert row["status"] == "failed"
        assert row["attempts"] == 0
        assert row["last_error"] == "client_no_longer_eligible"
        assert _failed_events(test_tenant) == []

    def test_uri_removed_since_queueing_is_skipped(self, test_tenant, make_client, queue):
        client = make_client()
        queue(client)
        database.oauth2.update_client(
            test_tenant["id"], client["client_id"], backchannel_logout_uri=""
        )
        assert _deliver(test_tenant, _RP(200))["skipped"] == 1

    def test_drains_more_than_one_batch(self, test_tenant, make_client, queue, mocker):
        mocker.patch.object(backchannel_service, "BATCH_SIZE", 2)
        client = make_client()
        for sid in ("s-1", "s-2", "s-3", "s-4", "s-5"):
            queue(client, sid=sid)
        rp = _RP(200)

        assert _deliver(test_tenant, rp)["delivered"] == 5
        assert len(rp.requests) == 5

    def test_builds_its_own_client_only_when_there_is_work(
        self, test_tenant, make_client, queue, mocker
    ):
        rp = _RP(200)
        build = mocker.patch.object(
            backchannel_service, "_build_http_client", side_effect=rp.client
        )
        with system_context():
            backchannel_service.deliver_due_backchannel_logouts(str(test_tenant["id"]))
        build.assert_not_called()

        queue(make_client())
        with system_context():
            counts = backchannel_service.deliver_due_backchannel_logouts(str(test_tenant["id"]))
        build.assert_called_once()
        assert counts["delivered"] == 1


class TestSafeClient:
    def test_uses_ssrf_guarded_client_with_dev_exceptions(self, mocker):
        build = mocker.patch.object(backchannel_service, "build_safe_client")
        backchannel_service._build_http_client()
        kwargs = build.call_args.kwargs
        assert kwargs["timeout"] == backchannel_service.HTTP_TIMEOUT_SECONDS
        assert kwargs["dev_hostname_allowlist"] == frozenset({"localhost.emobix.co.uk"})
        assert kwargs["dev_skip_tls_verify"] is True
        assert kwargs["dev_base_domain_rewrite"] is True


class TestCleanup:
    def test_reports_both_counts(self, mocker):
        purge = mocker.patch("database.oauth2.purge_finished_deliveries", return_value=3)
        sweep = mocker.patch("database.oauth2.sweep_stale_session_clients", return_value=2)

        result = backchannel_service.cleanup_backchannel_logout_state()

        assert result == {"deliveries_purged": 3, "session_records_swept": 2}
        purge.assert_called_once_with(older_than_days=30)
        sweep.assert_called_once_with(older_than_days=90)

    def test_due_tenants_are_listed(self, test_tenant, make_client, queue):
        queue(make_client())
        assert str(test_tenant["id"]) in (
            backchannel_service.list_tenants_with_due_backchannel_logouts()
        )
