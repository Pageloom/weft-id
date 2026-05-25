"""Tests for inbound SCIM credential REST API endpoints.

Covers `/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials`:
GET list, POST create (with the one-shot plaintext display), and DELETE
revoke. All endpoints require super_admin role.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
import settings
from schemas.scim_inbound import (
    ScimInboundToken,
    ScimInboundTokenCreated,
    ScimInboundTokenList,
)
from services.exceptions import ForbiddenError, NotFoundError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def api_user():
    tenant_id = str(uuid4())
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "role": "super_admin",
        "email": "admin@test.com",
        "first_name": "Admin",
        "last_name": "User",
        "tz": "UTC",
        "locale": "en_US",
    }


@pytest.fixture
def api_client(client, api_user, override_api_auth):
    override_api_auth(api_user, level="super_admin")
    return client


@pytest.fixture
def api_host():
    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup(api_user):
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": api_user["tenant_id"],
            "subdomain": "test",
        }
        yield


def _token(idp_id=None, **overrides):
    base = {
        "id": str(uuid4()),
        "idp_id": idp_id or str(uuid4()),
        "name": "Okta production",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }
    base.update(overrides)
    return ScimInboundToken(**base)


# ---------------------------------------------------------------------------
# GET list
# ---------------------------------------------------------------------------


class TestListInboundCredentials:
    def test_returns_list(self, api_client, api_host):
        idp_id = str(uuid4())
        items = [_token(idp_id=idp_id)]
        with patch(
            "services.scim.inbound_credentials.list_tokens",
            return_value=ScimInboundTokenList(items=items, total=1),
        ) as fn:
            resp = api_client.get(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        # Plaintext / hash never appear on the listing shape.
        assert "plaintext" not in body["items"][0]
        assert "token_hash" not in body["items"][0]
        assert fn.called

    def test_returns_404_when_idp_missing(self, api_client, api_host):
        idp_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.list_tokens",
            side_effect=NotFoundError(message="missing", code="idp_not_found"),
        ):
            resp = api_client.get(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host},
            )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST create
# ---------------------------------------------------------------------------


class TestCreateInboundCredential:
    def test_creates_and_returns_plaintext_once(self, api_client, api_host):
        """The plaintext is in the response body of the create call only.

        This is the only opportunity to read it; the database stores
        only the SHA-256 hash. The test pins the response shape so a
        future change that accidentally returned the hash or omitted
        the plaintext is caught.
        """
        idp_id = str(uuid4())
        new_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.create_token",
            return_value=ScimInboundTokenCreated(
                id=new_id,
                idp_id=idp_id,
                name="Okta production",
                created_at=datetime.now(UTC),
                plaintext="wid_inbound_secret-bearer-value",
            ),
        ) as fn:
            resp = api_client.post(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host, "Content-Type": "application/json"},
                json={"name": "Okta production"},
            )
        assert resp.status_code == 201
        body = resp.json()
        assert body["plaintext"] == "wid_inbound_secret-bearer-value"
        assert body["id"] == new_id
        assert body["idp_id"] == idp_id
        assert body["name"] == "Okta production"
        # Hash is never surfaced.
        assert "token_hash" not in body
        # The service receives the name kwarg.
        assert fn.call_args.kwargs.get("name") == "Okta production"

    def test_create_without_name(self, api_client, api_host):
        idp_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.create_token",
            return_value=ScimInboundTokenCreated(
                id=str(uuid4()),
                idp_id=idp_id,
                name=None,
                created_at=datetime.now(UTC),
                plaintext="wid_inbound_x",
            ),
        ) as fn:
            resp = api_client.post(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host, "Content-Type": "application/json"},
                json={},
            )
        assert resp.status_code == 201
        assert resp.json()["name"] is None
        # Service called with name=None (Pydantic default).
        assert fn.call_args.kwargs.get("name") is None

    def test_rejects_name_over_max_length(self, api_client, api_host):
        idp_id = str(uuid4())
        resp = api_client.post(
            f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
            headers={"host": api_host, "Content-Type": "application/json"},
            json={"name": "x" * 256},
        )
        assert resp.status_code == 422

    def test_rate_limit_returns_429(self, api_client, api_host):
        from services.exceptions import RateLimitError

        idp_id = str(uuid4())
        with patch(
            "routers.api.v1.saml_identity_providers.ratelimit.prevent",
            side_effect=RateLimitError(
                message="rate limited", limit=10, timespan=60, retry_after=60
            ),
        ):
            resp = api_client.post(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host, "Content-Type": "application/json"},
                json={},
            )
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After") == "60"

    def test_returns_404_when_idp_missing(self, api_client, api_host):
        idp_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.create_token",
            side_effect=NotFoundError(message="idp missing", code="idp_not_found"),
        ):
            resp = api_client.post(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host, "Content-Type": "application/json"},
                json={},
            )
        assert resp.status_code == 404

    def test_forbidden_propagates_from_service(self, api_client, api_host):
        """If the service raises ForbiddenError (e.g. a race), 403 is returned."""
        idp_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.create_token",
            side_effect=ForbiddenError(message="no", code="forbidden"),
        ):
            resp = api_client.post(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials",
                headers={"host": api_host, "Content-Type": "application/json"},
                json={},
            )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# DELETE revoke
# ---------------------------------------------------------------------------


class TestRevokeInboundCredential:
    def test_revokes_and_returns_204(self, api_client, api_host):
        idp_id = str(uuid4())
        token_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.revoke_token",
            return_value=None,
        ) as fn:
            resp = api_client.delete(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials/{token_id}",
                headers={"host": api_host},
            )
        assert resp.status_code == 204
        assert fn.call_args.args[1] == idp_id
        assert fn.call_args.args[2] == token_id

    def test_revoke_missing_token_returns_404(self, api_client, api_host):
        idp_id = str(uuid4())
        token_id = str(uuid4())
        with patch(
            "services.scim.inbound_credentials.revoke_token",
            side_effect=NotFoundError(message="missing", code="scim_inbound_token_not_found"),
        ):
            resp = api_client.delete(
                f"/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials/{token_id}",
                headers={"host": api_host},
            )
        assert resp.status_code == 404
