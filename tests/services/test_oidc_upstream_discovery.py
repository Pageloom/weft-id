"""Tests for OIDC upstream discovery.

Covers discovery parse, issuer mismatch rejection, non-https endpoint
rejection, TTL gating, and the SSRF guard (a discovery URL pointing at a
private/link-local address is refused). No live network calls: the safe
client is patched with a fake response.
"""

from unittest.mock import patch

import pytest
from services.oidc_upstream import discovery as discovery_service
from services.oidc_upstream.errors import (
    DiscoveryError,
    DiscoveryInsecureEndpointError,
    DiscoveryIssuerMismatchError,
    DiscoveryRedirectError,
)

from tests.fixtures.oidc import load_fixture

DISCOVERY_DOC = load_fixture("discovery")


class _FakeResponse:
    def __init__(self, status_code, json_body=None, text=""):
        self.status_code = status_code
        self._json_body = json_body
        self.text = text

    def json(self):
        if self._json_body is None:
            raise ValueError("no json")
        return self._json_body


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url):
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
            with pytest.raises(DiscoveryError):
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
