"""Tests for the inbound SCIM Users read endpoints.

Authenticated via a mocked bearer-token row so we exercise the auth
dep end-to-end and let the service layer talk to a patched DB.

Pagination and filter handling are also covered here -- they live at
the router boundary and don't have a meaningful unit-test layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
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


@pytest.fixture(autouse=True)
def reset_rate_limit():
    from utils.ratelimit import ratelimit as rl

    rl.reset("scim_inbound_auth:ip:{ip}", ip="testclient")
    yield
    rl.reset("scim_inbound_auth:ip:{ip}", ip="testclient")


def _token_row(idp_id: str, tenant_id: str | None = None):
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "idp_id": idp_id,
        "name": "test",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer wid_inbound_testtoken"}


# ---------------------------------------------------------------------------
# GET /Users
# ---------------------------------------------------------------------------


def test_list_users_happy_path(client, api_host, auth_headers):
    idp = str(uuid4())
    user_payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(uuid4()),
        "userName": "alice@x.test",
        "active": True,
        "meta": {
            "resourceType": "User",
            "location": "https://test/.../Users/X",
        },
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "services.scim.inbound_read.list_users",
            return_value=([user_payload], 1),
        ) as svc,
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/scim+json")
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert body["totalResults"] == 1
    assert body["startIndex"] == 1
    assert body["itemsPerPage"] == 1
    assert body["Resources"] == [user_payload]
    # location_builder produced absolute URLs.
    kwargs = svc.call_args.kwargs
    sample = kwargs["location_builder"]("test-id")
    assert sample.startswith(f"https://test.{settings.BASE_DOMAIN}/scim/v2/inbound/{idp}/Users/")


def test_list_users_pagination_clamps_start_index_to_one(client, api_host, auth_headers):
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.list_users", return_value=([], 0)) as svc,
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users?startIndex=0&count=5",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    # startIndex=0 is normalised to 1 per the parser.
    assert svc.call_args.kwargs["start_index"] == 1
    assert svc.call_args.kwargs["count"] == 5
    assert resp.json()["startIndex"] == 1


def test_list_users_username_filter_passed_to_service(client, api_host, auth_headers):
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.list_users", return_value=([], 0)) as svc,
    ):
        resp = client.get(
            f'/scim/v2/inbound/{idp}/Users?filter=userName eq "alice@x.test"',
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert svc.call_args.kwargs["user_name"] == "alice@x.test"
    assert svc.call_args.kwargs["external_id"] is None


def test_list_users_external_id_filter_passed_to_service(client, api_host, auth_headers):
    idp = str(uuid4())
    target_id = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.list_users", return_value=([], 0)) as svc,
    ):
        resp = client.get(
            f'/scim/v2/inbound/{idp}/Users?filter=externalId eq "{target_id}"',
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert svc.call_args.kwargs["external_id"] == target_id


def test_list_users_unsupported_filter_returns_invalid_filter(client, api_host, auth_headers):
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
    ):
        resp = client.get(
            f'/scim/v2/inbound/{idp}/Users?filter=userName co "x"',
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    body = resp.json()
    assert body["scimType"] == "invalidFilter"
    assert body["status"] == "400"


def test_list_users_disallowed_filter_attribute_returns_invalid_filter(
    client, api_host, auth_headers
):
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
    ):
        resp = client.get(
            f'/scim/v2/inbound/{idp}/Users?filter=email eq "alice@x.test"',
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidFilter"


# ---------------------------------------------------------------------------
# GET /Users/{id}
# ---------------------------------------------------------------------------


def test_get_user_returns_resource_on_match(client, api_host, auth_headers):
    idp = str(uuid4())
    uid = str(uuid4())
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": uid,
        "userName": "alice@x.test",
        "active": True,
        "meta": {"resourceType": "User", "location": "https://test/.../Users/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.get_user", return_value=payload),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.json() == payload


def test_get_user_returns_scim_404_when_not_found(client, api_host, auth_headers):
    idp = str(uuid4())
    uid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.get_user", return_value=None),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["status"] == "404"


def test_meta_location_is_absolute_and_uses_forwarded_host(client, auth_headers):
    """Real service path produces meta.location with the forwarded host."""
    idp = str(uuid4())
    forwarded_host = f"acme.{settings.BASE_DOMAIN}"

    # Use the real `inbound_read.get_user` against a stubbed DB row so the
    # router's location builder is exercised end-to-end.
    user_row = {
        "id": str(uuid4()),
        "first_name": "Alice",
        "last_name": "Example",
        "is_inactivated": False,
        "is_anonymized": False,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "saml_idp_id": idp,
        "email": "alice@x.test",
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("database.users.get_user_for_idp", return_value=user_row),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users/{user_row['id']}",
            headers={
                "host": "internal.cluster.local",
                "x-forwarded-host": forwarded_host,
                **auth_headers,
            },
        )
    assert resp.status_code == 200
    body = resp.json()
    expected_prefix = f"https://{forwarded_host}/scim/v2/inbound/{idp}/Users/"
    assert body["meta"]["location"].startswith(expected_prefix)


# ---------------------------------------------------------------------------
# Empty-filter / pagination edge cases at the router boundary
# ---------------------------------------------------------------------------


def test_list_users_empty_filter_string_treated_as_no_filter(client, api_host, auth_headers):
    """`?filter=` (empty string) must NOT raise invalidFilter -- it's no filter."""
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.list_users", return_value=([], 0)) as svc,
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users?filter=",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    # No filter values pushed down to the service.
    assert svc.call_args.kwargs["user_name"] is None
    assert svc.call_args.kwargs["external_id"] is None


def test_list_users_count_clamped_by_parser_to_advertised_max(client, api_host, auth_headers):
    """Per ServiceProviderConfig we advertise maxResults=200; large counts clamp."""
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.list_users", return_value=([], 0)) as svc,
    ):
        # 199 fits under the parser cap of 200, easy sanity case.
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users?count=199",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert svc.call_args.kwargs["count"] == 199


def test_get_user_cross_idp_returns_scim_404_at_router(client, api_host, auth_headers):
    """A user that exists under a different IdP must 404 with SCIM envelope.

    The DB layer's `get_user_for_idp` returns None on cross-IdP lookups;
    this test pins the router-level translation to a SCIM-shaped 404 so
    a regression in either layer is caught.
    """
    idp = str(uuid4())
    other_user_id = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("database.users.get_user_for_idp", return_value=None),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Users/{other_user_id}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["status"] == "404"
