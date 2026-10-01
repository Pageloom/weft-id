"""Tests for pairwise and public subject identifiers (services.oidc.subject)."""

import json
import string

import database
import httpx
import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.oidc import subject as svc

USER_ID = "6f1c2c1e-9a5f-4f0e-8a65-0c7b1f2d3e4f"
SECTOR_URI = "https://rp.example/redirect_uris.json"


def _client(**overrides) -> dict:
    return {
        "subject_type": "pairwise",
        "sector_identifier_uri": None,
        "redirect_uris": ["https://rp.example/cb", "https://rp.example/other"],
        **overrides,
    }


def _mock_http(monkeypatch, handler):
    """Route the sector document fetch through an in-process handler."""
    calls: list[str] = []

    def wrapped(request):
        calls.append(str(request.url))
        return handler(request)

    monkeypatch.setattr(
        svc,
        "build_safe_client",
        lambda **_: httpx.Client(transport=httpx.MockTransport(wrapped)),
    )
    return calls


def _serve(document, status=200):
    body = document if isinstance(document, bytes) else json.dumps(document).encode()
    return lambda request: httpx.Response(status, content=body)


# =============================================================================
# subject_for / subject_matches
# =============================================================================


class TestSubjectFor:
    def test_public_is_the_user_id(self):
        assert svc.subject_for(_client(subject_type="public"), USER_ID) == USER_ID

    def test_missing_subject_type_is_public(self):
        assert svc.subject_for({"redirect_uris": ["https://rp.example/cb"]}, USER_ID) == USER_ID

    def test_pairwise_is_opaque_and_url_safe(self):
        sub = svc.subject_for(_client(), USER_ID)
        assert sub != USER_ID
        assert len(sub) == 43
        assert set(sub) <= set(string.ascii_letters + string.digits + "-_")

    def test_pairwise_is_stable(self):
        assert svc.subject_for(_client(), USER_ID) == svc.subject_for(_client(), USER_ID)

    def test_same_sector_same_sub(self):
        other = _client(redirect_uris=["https://rp.example/elsewhere"])
        assert svc.subject_for(_client(), USER_ID) == svc.subject_for(other, USER_ID)

    def test_different_sector_different_sub(self):
        other = _client(redirect_uris=["https://other.example/cb"])
        assert svc.subject_for(_client(), USER_ID) != svc.subject_for(other, USER_ID)

    def test_different_user_different_sub(self):
        assert svc.subject_for(_client(), USER_ID) != svc.subject_for(_client(), "another-user")

    def test_sector_identifier_uri_host_is_the_sector(self):
        with_sector = _client(
            sector_identifier_uri="https://sector.example/uris.json",
            redirect_uris=["https://a.example/cb", "https://b.example/cb"],
        )
        same_host = _client(redirect_uris=["https://sector.example/cb"])
        assert svc.subject_for(with_sector, USER_ID) == svc.subject_for(same_host, USER_ID)

    def test_pairwise_without_sector_refuses(self):
        broken = _client(redirect_uris=["https://a.example/cb", "https://b.example/cb"])
        with pytest.raises(ValueError):
            svc.subject_for(broken, USER_ID)

    def test_matches(self):
        client = _client()
        assert svc.subject_matches(client, USER_ID, svc.subject_for(client, USER_ID))
        assert not svc.subject_matches(client, USER_ID, USER_ID)
        assert not svc.subject_matches(client, USER_ID, None)
        assert svc.subject_matches(_client(subject_type="public"), USER_ID, USER_ID)


class TestSectorHost:
    def test_from_redirect_uris(self):
        assert svc.sector_host(_client()) == "rp.example"

    def test_from_sector_identifier_uri(self):
        assert svc.sector_host(_client(sector_identifier_uri=SECTOR_URI.replace("rp.", "s."))) == (
            "s.example"
        )

    def test_none_without_redirects(self):
        assert svc.sector_host(_client(redirect_uris=[])) is None


# =============================================================================
# validate_subject_settings
# =============================================================================


class TestValidateSubjectSettings:
    def test_default_is_public(self):
        assert svc.validate_subject_settings(None, None, []) == ("public", None)

    def test_public_blank_sector_ok(self):
        assert svc.validate_subject_settings("public", "  ", ["https://rp.example/cb"]) == (
            "public",
            None,
        )

    def test_unknown_type(self):
        with pytest.raises(ValidationError) as exc:
            svc.validate_subject_settings("pseudonymous", None, ["https://rp.example/cb"])
        assert exc.value.code == svc.INVALID_SUBJECT_TYPE

    def test_public_with_sector_refused(self):
        with pytest.raises(ValidationError) as exc:
            svc.validate_subject_settings("public", SECTOR_URI, ["https://rp.example/cb"])
        assert exc.value.code == svc.INVALID_SECTOR_IDENTIFIER_URI

    def test_pairwise_one_host(self):
        uris = ["https://rp.example/cb", "https://rp.example:8443/cb"]
        assert svc.validate_subject_settings("pairwise", None, uris) == ("pairwise", None)

    @pytest.mark.parametrize(
        "uris", [[], ["https://a.example/cb", "https://b.example/cb"], ["not a uri"]]
    )
    def test_pairwise_without_single_host_refused(self, uris):
        with pytest.raises(ValidationError) as exc:
            svc.validate_subject_settings("pairwise", None, uris)
        assert exc.value.code == svc.INVALID_SECTOR_IDENTIFIER_URI

    @pytest.mark.parametrize(
        "uri",
        [
            "http://rp.example/uris.json",
            "/uris.json",
            "https://rp.example/uris.json#x",
            "https://rp.example/" + "x" * 2048,
        ],
    )
    def test_bad_sector_uri_refused_without_fetch(self, monkeypatch, uri):
        calls = _mock_http(monkeypatch, _serve([]))
        with pytest.raises(ValidationError) as exc:
            svc.validate_subject_settings("pairwise", uri, ["https://rp.example/cb"])
        assert exc.value.code == svc.INVALID_SECTOR_IDENTIFIER_URI
        assert calls == []

    def test_sector_document_lists_every_redirect(self, monkeypatch):
        uris = ["https://a.example/cb", "https://b.example/cb"]
        calls = _mock_http(monkeypatch, _serve([*uris, "https://c.example/cb"]))
        assert svc.validate_subject_settings("pairwise", f" {SECTOR_URI} ", uris) == (
            "pairwise",
            SECTOR_URI,
        )
        assert calls == [SECTOR_URI]

    def test_device_client_with_sector_document(self, monkeypatch):
        _mock_http(monkeypatch, _serve([]))
        assert svc.validate_subject_settings("pairwise", SECTOR_URI, []) == (
            "pairwise",
            SECTOR_URI,
        )

    @pytest.mark.parametrize(
        ("handler", "fragment"),
        [
            (_serve(["https://example.com/op"]), "missing"),
            (_serve([], status=404), "HTTP 404"),
            (_serve(b"not json"), "not JSON"),
            (_serve({"redirect_uris": []}), "JSON array"),
            (_serve([1, 2]), "JSON array"),
            (_serve(b"[" + b'"x",' * 10000 + b'"x"]'), "too large"),
        ],
    )
    def test_sector_document_problems(self, monkeypatch, handler, fragment):
        _mock_http(monkeypatch, handler)
        with pytest.raises(ValidationError) as exc:
            svc.validate_subject_settings("pairwise", SECTOR_URI, ["https://rp.example/cb"])
        assert exc.value.code == svc.INVALID_SECTOR_IDENTIFIER_URI
        assert fragment in exc.value.message

    def test_transport_failure(self, monkeypatch):
        def fail(request):
            raise httpx.ConnectError("refused")

        _mock_http(monkeypatch, fail)
        with pytest.raises(ValidationError) as exc:
            svc.validate_subject_settings("pairwise", SECTOR_URI, ["https://rp.example/cb"])
        assert "ConnectError" in exc.value.message


# =============================================================================
# set_client_subject_type (admin)
# =============================================================================


def _admin(test_tenant, test_admin_user, make_requesting_user, role="admin"):
    return make_requesting_user(
        user_id=str(test_admin_user["id"]), tenant_id=str(test_tenant["id"]), role=role
    )


def _events(test_tenant):
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=30)
        if e["event_type"] == "oauth2_client_subject_type_changed"
    ]


class TestSetClientSubjectType:
    def test_switch_to_pairwise_and_back(
        self, test_tenant, test_admin_user, normal_oauth2_client, make_requesting_user
    ):
        admin = _admin(test_tenant, test_admin_user, make_requesting_user)
        client_id = normal_oauth2_client["client_id"]

        updated = svc.set_client_subject_type(admin, client_id, subject_type="pairwise")
        assert updated["subject_type"] == "pairwise"
        assert updated["sector_identifier_uri"] is None
        (event,) = _events(test_tenant)
        assert event["actor_user_id"] == test_admin_user["id"]
        assert event["metadata"]["subject_type"] == "pairwise"
        assert event["metadata"]["previous_subject_type"] == "public"

        updated = svc.set_client_subject_type(admin, client_id, subject_type="public")
        assert updated["subject_type"] == "public"
        assert len(_events(test_tenant)) == 2

    def test_sector_identifier_uri_stored(
        self, monkeypatch, test_tenant, test_admin_user, normal_oauth2_client, make_requesting_user
    ):
        _mock_http(monkeypatch, _serve(normal_oauth2_client["redirect_uris"]))
        updated = svc.set_client_subject_type(
            _admin(test_tenant, test_admin_user, make_requesting_user),
            normal_oauth2_client["client_id"],
            subject_type="pairwise",
            sector_identifier_uri=SECTOR_URI,
        )
        assert updated["sector_identifier_uri"] == SECTOR_URI
        assert _events(test_tenant)[0]["metadata"]["sector_identifier_uri"] == SECTOR_URI

    def test_unchanged_logs_nothing(
        self, test_tenant, test_admin_user, normal_oauth2_client, make_requesting_user
    ):
        svc.set_client_subject_type(
            _admin(test_tenant, test_admin_user, make_requesting_user),
            normal_oauth2_client["client_id"],
            subject_type="public",
        )
        assert _events(test_tenant) == []

    def test_invalid_leaves_client_alone(
        self, monkeypatch, test_tenant, test_admin_user, normal_oauth2_client, make_requesting_user
    ):
        _mock_http(monkeypatch, _serve(["https://example.com/op"]))
        with pytest.raises(ValidationError):
            svc.set_client_subject_type(
                _admin(test_tenant, test_admin_user, make_requesting_user),
                normal_oauth2_client["client_id"],
                subject_type="pairwise",
                sector_identifier_uri=SECTOR_URI,
            )
        row = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert row["subject_type"] == "public"
        assert _events(test_tenant) == []

    def test_member_forbidden(
        self, test_tenant, test_admin_user, normal_oauth2_client, make_requesting_user
    ):
        with pytest.raises(ForbiddenError):
            svc.set_client_subject_type(
                _admin(test_tenant, test_admin_user, make_requesting_user, role="member"),
                normal_oauth2_client["client_id"],
                subject_type="pairwise",
            )

    def test_b2b_and_unknown_not_found(
        self, test_tenant, test_admin_user, b2b_oauth2_client, make_requesting_user
    ):
        admin = _admin(test_tenant, test_admin_user, make_requesting_user)
        for client_id in (b2b_oauth2_client["client_id"], "no-such-client"):
            with pytest.raises(NotFoundError):
                svc.set_client_subject_type(admin, client_id, subject_type="pairwise")
