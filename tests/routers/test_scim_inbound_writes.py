"""Tests for the inbound SCIM write endpoints (POST / PUT / PATCH / DELETE).

These exercise the FastAPI routes end-to-end with database calls mocked
out at module level. The service layer is exercised; the only thing
not exercised here is the real database.
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


def _token_row(idp_id: str, tenant_id: str | None = None) -> dict:
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
# POST /Users
# ---------------------------------------------------------------------------


def test_post_users_returns_201_with_location_header(client, api_host, auth_headers):
    idp = str(uuid4())
    new_id = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": new_id,
        "userName": "alice@x.test",
        "active": True,
        "meta": {
            "resourceType": "User",
            "location": f"https://{api_host}/scim/v2/inbound/{idp}/Users/{new_id}",
        },
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.users.create_or_merge_user",
            return_value=(resource, True),
        ),
    ):
        resp = client.post(
            f"/scim/v2/inbound/{idp}/Users",
            json={"userName": "alice@x.test", "externalId": "okta-1"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 201
    assert resp.headers["content-type"].startswith("application/scim+json")
    assert resp.headers["location"].endswith(f"/Users/{new_id}")
    assert resp.json()["id"] == new_id


def test_post_users_returns_200_on_merge(client, api_host, auth_headers):
    idp = str(uuid4())
    existing_id = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": existing_id,
        "userName": "alice@x.test",
        "active": True,
        "meta": {"resourceType": "User", "location": "https://x/.../Users/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.users.create_or_merge_user",
            return_value=(resource, False),
        ),
    ):
        resp = client.post(
            f"/scim/v2/inbound/{idp}/Users",
            json={"userName": "alice@x.test"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200


def test_post_users_translates_scim_write_error_to_scim_envelope(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.users.create_or_merge_user",
            side_effect=ScimWriteError(400, "no role for you", scim_type="mutability"),
        ),
    ):
        resp = client.post(
            f"/scim/v2/inbound/{idp}/Users",
            json={"userName": "x", "roles": ["admin"]},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["scimType"] == "mutability"


# ---------------------------------------------------------------------------
# PUT /Users/{id}
# ---------------------------------------------------------------------------


def test_put_user_replace(client, api_host, auth_headers):
    idp = str(uuid4())
    uid = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": uid,
        "userName": "alice@x.test",
        "active": True,
        "meta": {"resourceType": "User", "location": "https://x/.../Users/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("routers.scim.inbound.users.replace_user", return_value=resource) as svc,
    ):
        resp = client.put(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            json={"userName": "alice@x.test", "name": {"givenName": "A", "familyName": "B"}},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.json() == resource
    assert svc.call_args.args[2] == uid


def test_put_user_404_from_service(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    uid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.users.replace_user",
            side_effect=ScimWriteError(404, "User not found"),
        ),
    ):
        resp = client.put(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            json={"userName": "x"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /Users/{id}
# ---------------------------------------------------------------------------


def test_patch_user_basic(client, api_host, auth_headers):
    idp = str(uuid4())
    uid = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": uid,
        "userName": "alice@x.test",
        "active": False,
        "meta": {"resourceType": "User", "location": "https://x/.../Users/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("routers.scim.inbound.users.patch_user", return_value=resource),
    ):
        resp = client.patch(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_patch_user_invalid_filter_returns_scim_error(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    uid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.users.patch_user",
            side_effect=ScimWriteError(400, "bad path", scim_type="invalidPath"),
        ),
    ):
        resp = client.patch(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            json={"Operations": [{"op": "replace", "path": "garbage", "value": "x"}]},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidPath"


# ---------------------------------------------------------------------------
# DELETE /Users/{id}
# ---------------------------------------------------------------------------


def test_delete_user_returns_204(client, api_host, auth_headers):
    idp = str(uuid4())
    uid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("routers.scim.inbound.users.soft_delete_user") as svc,
    ):
        resp = client.delete(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 204
    assert resp.content == b""
    svc.assert_called_once()


def test_delete_user_404_when_cross_idp(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    uid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.users.soft_delete_user",
            side_effect=ScimWriteError(404, "User not found"),
        ),
    ):
        resp = client.delete(
            f"/scim/v2/inbound/{idp}/Users/{uid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth still required on write endpoints
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_write_endpoints_require_auth(client, api_host, method):
    idp = str(uuid4())
    uid = str(uuid4())
    base = f"/scim/v2/inbound/{idp}/Users"
    url = base if method == "post" else f"{base}/{uid}"
    fn = getattr(client, method)
    kwargs: dict = {"headers": {"host": api_host}}
    if method != "delete":
        kwargs["json"] = {"userName": "x"}
    resp = fn(url, **kwargs)
    assert resp.status_code == 401
    assert resp.json()["status"] == "401"
