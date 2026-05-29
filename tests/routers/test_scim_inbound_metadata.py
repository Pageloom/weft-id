"""Tests for the public-discovery SCIM metadata endpoints.

`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` are reachable
without a bearer token (per RFC 7644 §4 they're public discovery).
The tests pin the spec-mandated keys and the absolute `location`
URLs honouring `x-forwarded-host`.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
import settings


@pytest.fixture
def api_host():
    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup():
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": str(uuid4()),
            "subdomain": "test",
        }
        yield


def _idp_id():
    return str(uuid4())


def test_service_provider_config_returns_spec_shape(client, api_host):
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/ServiceProviderConfig",
        headers={"host": api_host},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/scim+json")
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]
    # Bulk explicitly NOT supported in this iteration.
    assert body["bulk"]["supported"] is False
    assert body["filter"]["supported"] is True
    assert body["patch"]["supported"] is True
    # Bearer is the primary auth scheme.
    schemes = body["authenticationSchemes"]
    assert any(s["type"] == "oauthbearertoken" and s.get("primary") for s in schemes)


def test_service_provider_config_uses_forwarded_host(client):
    """`location` URL honours x-forwarded-host (tenant subdomain)."""
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/ServiceProviderConfig",
        headers={
            "host": "internal.cluster.local",
            "x-forwarded-host": f"public-tenant.{settings.BASE_DOMAIN}",
        },
    )
    assert resp.status_code == 200
    loc = resp.json()["meta"]["location"]
    assert loc.startswith(f"https://public-tenant.{settings.BASE_DOMAIN}/")
    assert loc.endswith("/ServiceProviderConfig")


def test_resource_types_lists_user_and_group(client, api_host):
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/ResourceTypes",
        headers={"host": api_host},
    )
    assert resp.status_code == 200
    body = resp.json()
    names = {r["name"] for r in body["Resources"]}
    assert names == {"User", "Group"}
    # User must advertise the EnterpriseUser extension.
    user_rt = next(r for r in body["Resources"] if r["name"] == "User")
    extensions = {e["schema"] for e in user_rt.get("schemaExtensions", [])}
    assert "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User" in extensions


def test_resource_types_individual_get(client, api_host):
    idp = _idp_id()
    resp = client.get(f"/scim/v2/inbound/{idp}/ResourceTypes/User", headers={"host": api_host})
    assert resp.status_code == 200
    assert resp.json()["id"] == "User"


def test_resource_types_unknown_returns_scim_error(client, api_host):
    idp = _idp_id()
    resp = client.get(f"/scim/v2/inbound/{idp}/ResourceTypes/NotAThing", headers={"host": api_host})
    assert resp.status_code == 404
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["status"] == "404"


def test_schemas_lists_user_enterprise_and_group(client, api_host):
    idp = _idp_id()
    resp = client.get(f"/scim/v2/inbound/{idp}/Schemas", headers={"host": api_host})
    assert resp.status_code == 200
    body = resp.json()
    ids = {r["id"] for r in body["Resources"]}
    assert ids == {
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        "urn:ietf:params:scim:schemas:core:2.0:Group",
    }


def test_schema_individual_get_user(client, api_host):
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
        headers={"host": api_host},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"
    # Should have the headline attributes.
    attr_names = {a["name"] for a in body["attributes"]}
    assert {"userName", "externalId", "name", "emails", "active"}.issubset(attr_names)


def test_schema_unknown_returns_scim_error(client, api_host):
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/Schemas/urn:made:up:schema",
        headers={"host": api_host},
    )
    assert resp.status_code == 404
    assert resp.json()["status"] == "404"


# ---------------------------------------------------------------------------
# Public-discovery behaviour: metadata MUST NOT require a bearer token.
#
# RFC 7644 §4 specifies that ServiceProviderConfig / ResourceTypes /
# Schemas are public discovery endpoints. If a future refactor wires
# the bearer-auth dep onto them by accident, an IdP couldn't even read
# our capability advertisement without first guessing the right token,
# which defeats the whole purpose of discovery.
# ---------------------------------------------------------------------------


def test_metadata_endpoints_do_not_require_auth(client, api_host):
    """All three discovery endpoints return 200 with no Authorization header."""
    idp = _idp_id()
    for path in ("ServiceProviderConfig", "ResourceTypes", "Schemas"):
        resp = client.get(f"/scim/v2/inbound/{idp}/{path}", headers={"host": api_host})
        assert resp.status_code == 200, f"{path} required auth"


def test_metadata_endpoints_do_not_invoke_token_lookup(client, api_host):
    """Metadata endpoints must not even touch the token table.

    Even if they happened to short-circuit auth, exercising the DB
    lookup on a public endpoint would burn a query and create rate-
    limit pressure (the bearer-auth bucket is per-IP). Pin the
    no-side-effect contract.
    """
    idp = _idp_id()
    with patch("database.scim_inbound_tokens.get_by_hash") as get_by_hash:
        for path in ("ServiceProviderConfig", "ResourceTypes", "Schemas"):
            client.get(f"/scim/v2/inbound/{idp}/{path}", headers={"host": api_host})
    get_by_hash.assert_not_called()


def test_resource_types_locations_use_forwarded_host(client):
    """ResourceTypes `meta.location` entries honour x-forwarded-host."""
    idp = _idp_id()
    forwarded = f"acme.{settings.BASE_DOMAIN}"
    resp = client.get(
        f"/scim/v2/inbound/{idp}/ResourceTypes",
        headers={"host": "internal.cluster.local", "x-forwarded-host": forwarded},
    )
    assert resp.status_code == 200
    for rt in resp.json()["Resources"]:
        loc = rt["meta"]["location"]
        assert loc.startswith(f"https://{forwarded}/scim/v2/inbound/{idp}/ResourceTypes/")


def test_schemas_locations_use_forwarded_host(client):
    """Schemas list `meta.location` entries honour x-forwarded-host."""
    idp = _idp_id()
    forwarded = f"acme.{settings.BASE_DOMAIN}"
    resp = client.get(
        f"/scim/v2/inbound/{idp}/Schemas",
        headers={"host": "internal.cluster.local", "x-forwarded-host": forwarded},
    )
    assert resp.status_code == 200
    for schema in resp.json()["Resources"]:
        loc = schema["meta"]["location"]
        assert loc.startswith(f"https://{forwarded}/scim/v2/inbound/{idp}/Schemas/")


def test_schema_individual_get_enterprise_user(client, api_host):
    """The colon-bearing EnterpriseUser URN routes correctly via :path."""
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
        headers={"host": api_host},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    attr_names = {a["name"] for a in body["attributes"]}
    assert "employeeNumber" in attr_names
    assert "department" in attr_names


def test_metadata_open_but_user_and_group_endpoints_require_bearer(client, api_host):
    """Pin RFC 7644 §4 invariant: discovery is public, data endpoints require auth.

    Specifically:
    * `ServiceProviderConfig`, `ResourceTypes`, `Schemas` MUST return 200
      with no `Authorization` header (otherwise a SCIM client couldn't
      even discover our capabilities).
    * `Users` and `Groups` MUST return the byte-identical SCIM 2.0 401
      envelope with no `Authorization` header.

    A future refactor that wires the bearer dep onto the discovery routes
    -- or that accidentally drops it from `/Users` or `/Groups` -- would
    break this test. The /Users + /Groups 401 envelope check also pins
    the "same body shape across auth-failure modes" invariant from
    iteration 2 (no tenant / IdP leak).
    """
    idp = _idp_id()

    # Discovery endpoints: 200 with no Authorization header.
    for path in ("ServiceProviderConfig", "ResourceTypes", "Schemas"):
        resp = client.get(f"/scim/v2/inbound/{idp}/{path}", headers={"host": api_host})
        assert resp.status_code == 200, f"{path} should be public-discovery"

    # Data endpoints: 401 with the SCIM error envelope and no Authorization.
    for path in ("Users", "Groups"):
        resp = client.get(f"/scim/v2/inbound/{idp}/{path}", headers={"host": api_host})
        assert resp.status_code == 401, f"{path} should require bearer auth"
        body = resp.json()
        assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
        assert body["status"] == "401"
        assert body["detail"] == "Authentication required"
        assert resp.headers.get("WWW-Authenticate", "").startswith("Bearer")


def test_schema_individual_get_group(client, api_host):
    """The Group schema URN routes correctly via :path."""
    idp = _idp_id()
    resp = client.get(
        f"/scim/v2/inbound/{idp}/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
        headers={"host": api_host},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group"
    attr_names = {a["name"] for a in body["attributes"]}
    assert {"displayName", "members"}.issubset(attr_names)
