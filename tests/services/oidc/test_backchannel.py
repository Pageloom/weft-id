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
        # Hide the fresh delivery from the dev worker, which shares this
        # database and would otherwise race the test to claim it; ``_deliver``
        # makes it due again just before its own claim.
        database.execute(
            str(test_tenant["id"]),
            """
            update oidc_backchannel_logout_deliveries
            set next_attempt_at = now() + interval '1 hour'
            where status = 'pending' and attempts = 0
            """,
        )

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


def _release(test_tenant) -> None:
    """Make the deliveries ``queue`` hid from the dev worker due now.

    Retried deliveries (attempts > 0) keep their schedule.
    """
    database.execute(
        str(test_tenant["id"]),
        """
        update oidc_backchannel_logout_deliveries set next_attempt_at = now()
        where status = 'pending' and attempts = 0
        """,
    )


def _deliver(test_tenant, rp: _RP) -> dict:
    _release(test_tenant)
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
        _release(test_tenant)
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
        _release(test_tenant)
        assert str(test_tenant["id"]) in (
            backchannel_service.list_tenants_with_due_backchannel_logouts()
        )


# ---------------------------------------------------------------------------
# Guard refusals are recorded generically (no internal-network oracle)
# ---------------------------------------------------------------------------


class TestBlockedDestination:
    @pytest.mark.parametrize(
        "message",
        [
            "target resolves to a private or reserved address",
            "target hostname could not be resolved: intranet.corp",
        ],
    )
    def test_guard_refusal_is_blocked_destination(self, test_tenant, make_client, queue, message):
        from utils.safe_http import SsrfBlockedError

        queue(make_client())

        counts = _deliver(test_tenant, _RP(exc=SsrfBlockedError(message)))

        assert counts["retried"] == 1
        row = _row(test_tenant)
        assert row["last_error"] == "blocked_destination"
        assert "intranet" not in row["last_error"]


# ---------------------------------------------------------------------------
# Admin read: list_backchannel_logout_deliveries
# ---------------------------------------------------------------------------


def _admin(test_tenant, user, role="admin"):
    from services.types import RequestingUser

    return RequestingUser(id=str(user["id"]), tenant_id=str(test_tenant["id"]), role=role)


class TestListDeliveries:
    def test_lists_newest_first_with_counts_and_tracks_activity(
        self, test_tenant, test_admin_user, test_user, make_client, queue
    ):
        from unittest.mock import patch

        client = make_client()
        queue(client, sid="s-1")
        _deliver(test_tenant, _RP(200))
        queue(client, sid="s-2")

        with patch("services.oidc.backchannel.track_activity") as track:
            result = backchannel_service.list_backchannel_logout_deliveries(
                _admin(test_tenant, test_admin_user), client["client_id"]
            )

        track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))
        assert result.total == 2
        assert result.page == 1 and result.limit == 20
        assert result.counts.model_dump() == {"pending": 1, "delivered": 1, "failed": 0}
        pending, delivered = result.items
        assert pending.status == "pending"
        assert pending.next_attempt_at is not None
        assert delivered.status == "delivered"
        assert delivered.next_attempt_at is None  # only meaningful while pending
        assert delivered.attempts == 1
        assert delivered.last_http_status == 200
        assert delivered.user_id == str(test_user["id"])
        assert delivered.user_email == test_user["email"]
        assert delivered.user_name == f"{test_user['first_name']} {test_user['last_name']}"

    def test_status_filter_and_paging(self, test_tenant, test_admin_user, make_client, queue):
        client = make_client()
        for i in range(3):
            queue(client, sid=f"s-{i}")
        admin = _admin(test_tenant, test_admin_user)

        page2 = backchannel_service.list_backchannel_logout_deliveries(
            admin, client["client_id"], page=2, limit=2
        )
        assert len(page2.items) == 1 and page2.total == 3

        delivered = backchannel_service.list_backchannel_logout_deliveries(
            admin, client["client_id"], status="delivered"
        )
        assert delivered.items == [] and delivered.total == 0
        assert delivered.counts.pending == 3

    def test_deleted_user_has_no_name(
        self, test_tenant, test_admin_user, test_user, make_client, queue
    ):
        client = make_client()
        queue(client)
        database.execute(
            str(test_tenant["id"]), "delete from users where id = :id", {"id": test_user["id"]}
        )
        (item,) = backchannel_service.list_backchannel_logout_deliveries(
            _admin(test_tenant, test_admin_user), client["client_id"]
        ).items
        assert item.user_id == str(test_user["id"])
        assert item.user_name is None and item.user_email is None

    def test_member_is_forbidden(self, test_tenant, test_user, make_client):
        from services.exceptions import ForbiddenError

        client = make_client()
        with pytest.raises(ForbiddenError):
            backchannel_service.list_backchannel_logout_deliveries(
                _admin(test_tenant, test_user, role="member"), client["client_id"]
            )

    def test_unknown_client(self, test_tenant, test_admin_user):
        from services.exceptions import NotFoundError

        with pytest.raises(NotFoundError):
            backchannel_service.list_backchannel_logout_deliveries(
                _admin(test_tenant, test_admin_user), "weft-id_client_nope"
            )

    def test_b2b_client_rejected(self, test_tenant, test_admin_user, b2b_oauth2_client):
        from services.exceptions import ValidationError

        with pytest.raises(ValidationError) as exc:
            backchannel_service.list_backchannel_logout_deliveries(
                _admin(test_tenant, test_admin_user), b2b_oauth2_client["client_id"]
            )
        assert exc.value.code == "backchannel_logout_not_supported_for_client_type"

    def test_invalid_status_rejected(self, test_tenant, test_admin_user, make_client):
        from services.exceptions import ValidationError

        client = make_client()
        with pytest.raises(ValidationError) as exc:
            backchannel_service.list_backchannel_logout_deliveries(
                _admin(test_tenant, test_admin_user), client["client_id"], status="bogus"
            )
        assert exc.value.code == "invalid_delivery_status"

    def test_other_tenant_client_not_found(self, test_tenant, test_admin_user, make_client):
        import uuid

        from services.exceptions import NotFoundError
        from services.types import RequestingUser

        client = make_client()
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, 'Other') returning id",
            {"s": f"other-{uuid.uuid4().hex[:8]}"},
        )
        try:
            with pytest.raises(NotFoundError):
                backchannel_service.list_backchannel_logout_deliveries(
                    RequestingUser(
                        id=str(test_admin_user["id"]), tenant_id=str(other["id"]), role="admin"
                    ),
                    client["client_id"],
                )
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
            )
