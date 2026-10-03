"""Tests for OIDC upstream discovery.

Covers discovery parse, issuer mismatch rejection, non-https endpoint
rejection, TTL gating, and the SSRF guard (a discovery URL pointing at a
private/link-local address is refused). No live network calls: the safe
client is patched with a fake response.
"""

import json
from unittest.mock import patch

import pytest
from services.oidc_upstream import discovery as discovery_service
from services.oidc_upstream.errors import (
    DiscoveryError,
    DiscoveryInsecureEndpointError,
    DiscoveryIssuerMismatchError,
    DiscoveryRedirectError,
    DiscoveryUnavailableError,
)

from tests.fixtures.oidc import load_fixture

DISCOVERY_DOC = load_fixture("discovery")


class _FakeResponse:
    def __init__(self, status_code, json_body=None, text=""):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield b"not json" if self._json_body is None else json.dumps(self._json_body).encode()


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        return self._response


def _patch_client(response):
    return patch(
        "services.oidc_upstream.discovery.build_safe_client",
        return_value=_FakeClient(response),
    )


def _make_connection(tenant, **overrides):
    from uuid import uuid4

    import database

    created_by = str(
        database.fetchone(
            tenant["id"],
            """
            INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
            VALUES (:tenant_id, :password_hash, 'T', 'U', 'member')
            RETURNING id
            """,
            {"tenant_id": tenant["id"], "password_hash": "x" * 60},
        )["id"]
    )
    row = database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=f"Discovery Test {uuid4().hex[:8]}",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=created_by,
        **overrides,
    )
    return row


class TestRunDiscovery:
    def test_parses_and_persists_endpoints(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(200, DISCOVERY_DOC)):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

        assert row["authorization_endpoint"] == "https://idp.example.com/authorize"
        assert row["token_endpoint"] == "https://idp.example.com/token"
        assert row["userinfo_endpoint"] == "https://idp.example.com/userinfo"
        assert row["jwks_uri"] == "https://idp.example.com/jwks"
        assert row["discovery_fetched_at"] is not None
        assert row["discovery_error"] is None

    def test_userinfo_endpoint_optional(self, test_tenant):
        """userinfo_endpoint is RECOMMENDED, not REQUIRED -- absent is accepted."""
        conn = _make_connection(test_tenant)
        doc = dict(DISCOVERY_DOC)
        del doc["userinfo_endpoint"]
        with _patch_client(_FakeResponse(200, doc)):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

        assert row["authorization_endpoint"] == "https://idp.example.com/authorize"
        assert row["token_endpoint"] == "https://idp.example.com/token"
        assert row["jwks_uri"] == "https://idp.example.com/jwks"
        assert row["userinfo_endpoint"] is None
        assert row["discovery_error"] is None

    def test_end_session_endpoint_persisted(self, test_tenant):
        conn = _make_connection(test_tenant)
        doc = dict(DISCOVERY_DOC, end_session_endpoint="https://idp.example.com/logout")
        with _patch_client(_FakeResponse(200, doc)):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))
        assert row["end_session_endpoint"] == "https://idp.example.com/logout"

    def test_end_session_endpoint_cleared_when_no_longer_published(self, test_tenant):
        import database

        conn = _make_connection(test_tenant)
        database.oidc_upstream.update_connection(
            test_tenant["id"], str(conn["id"]), end_session_endpoint="https://old.example/logout"
        )
        doc = {k: v for k, v in DISCOVERY_DOC.items() if k != "end_session_endpoint"}
        with _patch_client(_FakeResponse(200, doc)):
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]), force=True)
        assert row["end_session_endpoint"] is None

    def test_non_https_end_session_endpoint_rejected(self, test_tenant):
        conn = _make_connection(test_tenant)
        bad_doc = dict(DISCOVERY_DOC, end_session_endpoint="http://idp.example.com/logout")
        with patch("services.oidc_upstream.discovery.settings.IS_DEV", False):
            with _patch_client(_FakeResponse(200, bad_doc)):
                with pytest.raises(DiscoveryInsecureEndpointError):
                    discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

    def test_issuer_mismatch_rejected(self, test_tenant):
        conn = _make_connection(test_tenant)
        bad_doc = dict(DISCOVERY_DOC, issuer="https://evil.example.com")
        with _patch_client(_FakeResponse(200, bad_doc)):
            with pytest.raises(DiscoveryIssuerMismatchError):
                discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

        # Error recorded, prior endpoints left intact.
        import database

        refreshed = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
        assert refreshed["discovery_error"] is not None
        assert refreshed["authorization_endpoint"] is None

    def test_non_https_endpoint_rejected(self, test_tenant):
        conn = _make_connection(test_tenant)
        bad_doc = dict(DISCOVERY_DOC, token_endpoint="http://idp.example.com/token")
        # IS_DEV is true in tests, which permits http; force production mode
        # so the https requirement is actually exercised.
        with patch("services.oidc_upstream.discovery.settings.IS_DEV", False):
            with _patch_client(_FakeResponse(200, bad_doc)):
                with pytest.raises(DiscoveryInsecureEndpointError):
                    discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

    def test_redirect_rejected(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(302)):
            with pytest.raises(DiscoveryRedirectError):
                discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

    def test_http_error_recorded(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(500)):
            with pytest.raises(DiscoveryUnavailableError):
                discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

        import database

        refreshed = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
        assert refreshed["discovery_error"] is not None

    def test_ttl_gates_refetch(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(200, DISCOVERY_DOC)):
            discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

        # A second run within the TTL is a no-op (no client call).
        with _patch_client(_FakeResponse(500)) as mock:
            row = discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))
            assert mock.call_count == 0
        assert row["authorization_endpoint"] == "https://idp.example.com/authorize"

    def test_force_bypasses_ttl(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(200, DISCOVERY_DOC)):
            discovery_service.run_discovery(test_tenant["id"], str(conn["id"]))

        with _patch_client(_FakeResponse(200, DISCOVERY_DOC)) as mock:
            discovery_service.run_discovery(test_tenant["id"], str(conn["id"]), force=True)
            assert mock.call_count == 1

    def test_missing_connection_raises(self, test_tenant):
        from uuid import uuid4

        with pytest.raises(DiscoveryError):
            discovery_service.run_discovery(test_tenant["id"], str(uuid4()))


class TestSsrFGuard:
    def test_private_address_refused(self):
        """A discovery URL resolving to a private address is refused by the
        real SSRF guard (no patching of build_safe_client)."""

        with pytest.raises(DiscoveryError):
            discovery_service._fetch_discovery_document("http://127.0.0.1/well-known")

    def test_link_local_address_refused(self):

        with pytest.raises(DiscoveryError):
            discovery_service._fetch_discovery_document("http://169.254.169.254/latest/meta-data")


class TestDevBaseDomainRewrite:
    def test_fetch_discovery_passes_flag(self):
        """Opts into the dev-only base-domain rewrite (loopback E2E); inert
        outside IS_DEV."""
        with _patch_client(_FakeResponse(200, {"issuer": "x"})) as mock_client:
            discovery_service._fetch_discovery_document("https://idp.example.com/.well-known")
        assert mock_client.call_args.kwargs["dev_base_domain_rewrite"] is True
        assert mock_client.call_args.kwargs["dev_hostname_allowlist"] == frozenset(
            {"localhost.emobix.co.uk"}
        )


class _RaisingClient(_FakeClient):
    def stream(self, method, url, **kwargs):
        raise OSError("connection refused")


def _age_discovery(tenant, conn_id, hours=2):
    import database

    database.execute(
        tenant["id"],
        "update oidc_idp_connections set discovery_fetched_at = now() - make_interval(hours => :h)"
        " where id = :id",
        {"h": hours, "id": conn_id},
    )
    return database.oidc_upstream.get_connection(tenant["id"], conn_id)


def _discovered(tenant):
    conn = _make_connection(tenant)
    with _patch_client(_FakeResponse(200, DISCOVERY_DOC)):
        return discovery_service.run_discovery(tenant["id"], str(conn["id"]))


class TestRefreshForLogin:
    def test_fresh_connection_not_refetched(self, test_tenant):
        conn = _discovered(test_tenant)
        with _patch_client(_FakeResponse(500)) as mock:
            row = discovery_service.refresh_for_login(test_tenant["id"], conn)
            assert mock.call_count == 0
        assert row is conn

    def test_stale_connection_refetched(self, test_tenant):
        conn = _age_discovery(test_tenant, str(_discovered(test_tenant)["id"]))
        moved = dict(DISCOVERY_DOC, jwks_uri="https://idp.example.com/jwks-rotated")
        with _patch_client(_FakeResponse(200, moved)) as mock:
            row = discovery_service.refresh_for_login(test_tenant["id"], conn)
            assert mock.call_count == 1
        assert row["jwks_uri"] == "https://idp.example.com/jwks-rotated"
        assert row["discovery_fetched_at"] > conn["discovery_fetched_at"]

    def test_never_discovered_without_endpoints_is_discovered(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(200, DISCOVERY_DOC)):
            row = discovery_service.refresh_for_login(test_tenant["id"], conn)
        assert row["token_endpoint"] == "https://idp.example.com/token"

    def test_hand_set_endpoints_not_refetched(self, test_tenant):
        conn = _make_connection(
            test_tenant,
            authorization_endpoint="https://idp.example.com/authorize",
            token_endpoint="https://idp.example.com/token",
            jwks_uri="https://idp.example.com/jwks",
        )
        with _patch_client(_FakeResponse(500)) as mock:
            row = discovery_service.refresh_for_login(test_tenant["id"], conn)
            assert mock.call_count == 0
        assert row is conn

    @pytest.mark.parametrize(
        "client",
        [_FakeClient(_FakeResponse(503)), _RaisingClient(None)],
        ids=["http-503", "transport"],
    )
    def test_unavailable_falls_back_to_stored_endpoints(self, test_tenant, client):
        conn = _age_discovery(test_tenant, str(_discovered(test_tenant)["id"]))
        with patch("services.oidc_upstream.discovery.build_safe_client", return_value=client):
            row = discovery_service.refresh_for_login(test_tenant["id"], conn)
        assert row["token_endpoint"] == "https://idp.example.com/token"

    def test_unavailable_without_endpoints_raises(self, test_tenant):
        conn = _make_connection(test_tenant)
        with _patch_client(_FakeResponse(503)):
            with pytest.raises(DiscoveryUnavailableError):
                discovery_service.refresh_for_login(test_tenant["id"], conn)

    @pytest.mark.parametrize(
        ("response", "error"),
        [
            (
                _FakeResponse(200, dict(DISCOVERY_DOC, issuer="https://evil.example.com")),
                DiscoveryIssuerMismatchError,
            ),
            (
                _FakeResponse(200, dict(DISCOVERY_DOC, token_endpoint="http://idp.example.com/t")),
                DiscoveryInsecureEndpointError,
            ),
            (_FakeResponse(302), DiscoveryRedirectError),
            (_FakeResponse(200, None), DiscoveryError),
        ],
        ids=["issuer-mismatch", "insecure", "redirect", "not-json"],
    )
    def test_refused_document_raises_and_keeps_old_endpoints(
        self, test_tenant, response, error, monkeypatch
    ):
        """A document WeftID refuses stops the sign-in (no fallback), and the
        stored endpoints are left for the admin to inspect."""
        import database
        import settings

        monkeypatch.setattr(settings, "IS_DEV", False)
        conn = _age_discovery(test_tenant, str(_discovered(test_tenant)["id"]))
        with _patch_client(response):
            with pytest.raises(error) as exc:
                discovery_service.refresh_for_login(test_tenant["id"], conn)
        assert not isinstance(exc.value, DiscoveryUnavailableError)

        row = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
        assert row["token_endpoint"] == "https://idp.example.com/token"
        assert row["discovery_error"] is not None
        # Still stale, so the next sign-in tries again rather than trusting it.
        assert row["discovery_fetched_at"] == conn["discovery_fetched_at"]
