"""Service tests: pushed authorization requests (RFC 9126)."""

import hashlib

import database
import pytest
from services import oauth2_par as par_service
from services.exceptions import ValidationError


@pytest.fixture
def par_client(test_tenant, test_admin_user):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="PAR App",
        redirect_uris=["https://app.example.com/callback"],
        created_by=str(test_admin_user["id"]),
    )


def _rows(test_tenant) -> list[dict]:
    return database.fetchall(
        test_tenant["id"],
        "select reference_hash, parameters, expires_at, created_at "
        "from oauth2_pushed_authorization_requests",
        {},
    )


class TestIsPushedRequestUri:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("urn:ietf:params:oauth:request_uri:abc", True),
            ("urn:ietf:params:oauth:request_uri:", True),
            ("https://rp.example/ro", False),
            ("", False),
            (None, False),
        ],
    )
    def test_prefix(self, value, expected):
        assert par_service.is_pushed_request_uri(value) is expected


class TestPush:
    def test_stores_hash_and_parameters(self, test_tenant, par_client, mocker):
        mocker.patch("services.oauth2_par.log_event")
        pushed = par_service.push_authorization_request(
            test_tenant["id"], par_client, {"scope": "openid", "state": "s"}
        )
        assert pushed.request_uri.startswith(par_service.REQUEST_URI_PREFIX)
        assert pushed.expires_in == par_service.EXPIRES_IN
        reference = pushed.request_uri.removeprefix(par_service.REQUEST_URI_PREFIX)
        (row,) = _rows(test_tenant)
        # Only the hash of the reference is stored.
        assert row["reference_hash"] == hashlib.sha256(reference.encode()).hexdigest()
        assert reference not in row["reference_hash"]
        assert row["parameters"] == {"scope": "openid", "state": "s"}
        lifetime = (row["expires_at"] - row["created_at"]).total_seconds()
        assert 59 <= lifetime <= 61

    def test_logs_event(self, test_tenant, par_client, mocker):
        log = mocker.patch("services.oauth2_par.log_event")
        par_service.push_authorization_request(test_tenant["id"], par_client, {"scope": "openid"})
        kwargs = log.call_args.kwargs
        assert kwargs["event_type"] == "oauth2_authorization_request_pushed"
        assert kwargs["actor_user_id"] == par_service.SYSTEM_ACTOR_ID
        assert kwargs["artifact_type"] == "oauth2_client"
        assert kwargs["artifact_id"] == str(par_client["id"])
        assert kwargs["metadata"]["client_id"] == par_client["client_id"]
        assert kwargs["metadata"]["client_name"] == "PAR App"
        assert kwargs["metadata"]["scope"] == "openid"
        assert kwargs["metadata"]["pushed_request_id"]

    def test_event_recorded(self, test_tenant, par_client):
        par_service.push_authorization_request(test_tenant["id"], par_client, {})
        events = database.fetchall(
            test_tenant["id"],
            "select event_type from event_logs where artifact_id = :id",
            {"id": str(par_client["id"])},
        )
        assert "oauth2_authorization_request_pushed" in [e["event_type"] for e in events]


class TestStoreForResume:
    def test_new_request_uri_with_given_lifetime_and_no_event(
        self, test_tenant, par_client, mocker
    ):
        log = mocker.patch("services.oauth2_par.log_event")
        request_uri = par_service.store_for_resume(
            test_tenant["id"], par_client, {"state": "s"}, 600
        )
        assert request_uri.startswith(par_service.REQUEST_URI_PREFIX)
        log.assert_not_called()
        (row,) = _rows(test_tenant)
        assert 599 <= (row["expires_at"] - row["created_at"]).total_seconds() <= 601
        assert par_service.redeem_pushed_request(test_tenant["id"], par_client, request_uri) == {
            "state": "s"
        }


class TestRedeem:
    def test_once(self, test_tenant, par_client, mocker):
        mocker.patch("services.oauth2_par.log_event")
        pushed = par_service.push_authorization_request(
            test_tenant["id"], par_client, {"state": "s"}
        )
        params = par_service.redeem_pushed_request(
            test_tenant["id"], par_client, pushed.request_uri
        )
        assert params == {"state": "s"}
        with pytest.raises(ValidationError) as exc:
            par_service.redeem_pushed_request(test_tenant["id"], par_client, pushed.request_uri)
        assert exc.value.code == "invalid_request_uri"

    def test_other_client_refused(self, test_tenant, test_admin_user, par_client, mocker):
        mocker.patch("services.oauth2_par.log_event")
        other = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Other",
            redirect_uris=["https://other.example/cb"],
            created_by=str(test_admin_user["id"]),
        )
        pushed = par_service.push_authorization_request(test_tenant["id"], par_client, {})
        with pytest.raises(ValidationError):
            par_service.redeem_pushed_request(test_tenant["id"], other, pushed.request_uri)

    @pytest.mark.parametrize(
        "request_uri",
        [
            "urn:ietf:params:oauth:request_uri:",
            "urn:ietf:params:oauth:request_uri:" + "a" * 129,
            "urn:ietf:params:oauth:request_uri:unknown",
        ],
    )
    def test_bad_reference_refused_and_logged(
        self, test_tenant, par_client, request_uri, mocker, caplog
    ):
        consume = mocker.spy(database.oauth2, "consume_pushed_request")
        with caplog.at_level("INFO", logger="services.oauth2_par"):
            with pytest.raises(ValidationError) as exc:
                par_service.redeem_pushed_request(test_tenant["id"], par_client, request_uri)
        assert exc.value.code == "invalid_request_uri"
        assert "already used" in exc.value.message
        assert par_client["client_id"] in caplog.text
        # Empty and over-long references never reach the database.
        reference = request_uri.removeprefix(par_service.REQUEST_URI_PREFIX)
        assert consume.called is (0 < len(reference) <= 128)
