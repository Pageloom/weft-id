"""Tests for the inbound SCIM Group write endpoints (POST / PUT / PATCH / DELETE).

These exercise the FastAPI routes end-to-end with the service layer mocked
out so we exercise the router boundary contract -- the deeper service-layer
behaviour is covered by `tests/services/scim/test_inbound_group_write*.py`.
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


def _token_row(idp_id: str) -> dict:
    return {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
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
# POST /Groups
# ---------------------------------------------------------------------------


def test_post_groups_returns_201_with_location_header(client, api_host, auth_headers):
    idp = str(uuid4())
    new_id = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": new_id,
        "displayName": "Engineering",
        "members": [],
        "meta": {
            "resourceType": "Group",
            "location": f"https://{api_host}/scim/v2/inbound/{idp}/Groups/{new_id}",
        },
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.groups.create_group",
            return_value=resource,
        ),
    ):
        resp = client.post(
            f"/scim/v2/inbound/{idp}/Groups",
            json={"displayName": "Engineering"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 201
    assert resp.headers["content-type"].startswith("application/scim+json")
    assert resp.headers["location"].endswith(f"/Groups/{new_id}")
    assert resp.json()["id"] == new_id


def test_post_groups_translates_uniqueness_to_scim_409(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.groups.create_group",
            side_effect=ScimWriteError(409, "duplicate", scim_type="uniqueness"),
        ),
    ):
        resp = client.post(
            f"/scim/v2/inbound/{idp}/Groups",
            json={"displayName": "Engineering"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 409
    body = resp.json()
    assert body["status"] == "409"
    assert body["scimType"] == "uniqueness"


def test_post_groups_translates_invalid_value_to_scim_400(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.groups.create_group",
            side_effect=ScimWriteError(400, "no user", scim_type="invalidValue"),
        ),
    ):
        resp = client.post(
            f"/scim/v2/inbound/{idp}/Groups",
            json={"displayName": "Engineering", "members": [{"value": "nobody"}]},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidValue"


# ---------------------------------------------------------------------------
# PUT /Groups/{id}
# ---------------------------------------------------------------------------


def test_put_group_replace(client, api_host, auth_headers):
    idp = str(uuid4())
    gid = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": gid,
        "displayName": "Engineering 2",
        "members": [],
        "meta": {"resourceType": "Group", "location": "https://x/.../Groups/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("routers.scim.inbound.groups.replace_group", return_value=resource) as svc,
    ):
        resp = client.put(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            json={"displayName": "Engineering 2"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.json() == resource
    assert svc.call_args.args[2] == gid


def test_put_group_404_from_service(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    gid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.groups.replace_group",
            side_effect=ScimWriteError(404, "Group not found"),
        ),
    ):
        resp = client.put(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            json={"displayName": "x"},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PATCH /Groups/{id}
# ---------------------------------------------------------------------------


def test_patch_group_basic(client, api_host, auth_headers):
    idp = str(uuid4())
    gid = str(uuid4())
    resource = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": gid,
        "displayName": "Renamed",
        "members": [],
        "meta": {"resourceType": "Group", "location": "https://x/.../Groups/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("routers.scim.inbound.groups.patch_group", return_value=resource),
    ):
        resp = client.patch(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            json={"Operations": [{"op": "replace", "path": "displayName", "value": "Renamed"}]},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.json()["displayName"] == "Renamed"


def test_patch_group_invalid_path_returns_scim_error(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    gid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.groups.patch_group",
            side_effect=ScimWriteError(400, "bad path", scim_type="invalidPath"),
        ),
    ):
        resp = client.patch(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            json={"Operations": [{"op": "replace", "path": "garbage", "value": "x"}]},
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidPath"


# ---------------------------------------------------------------------------
# DELETE /Groups/{id}
# ---------------------------------------------------------------------------


def test_delete_group_returns_204(client, api_host, auth_headers):
    idp = str(uuid4())
    gid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("routers.scim.inbound.groups.delete_group") as svc,
    ):
        resp = client.delete(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 204
    assert resp.content == b""
    svc.assert_called_once()


def test_delete_group_404_when_cross_idp(client, api_host, auth_headers):
    from services.scim.inbound_write import ScimWriteError

    idp = str(uuid4())
    gid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "routers.scim.inbound.groups.delete_group",
            side_effect=ScimWriteError(404, "Group not found"),
        ),
    ):
        resp = client.delete(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth required on write endpoints
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_group_write_endpoints_require_auth(client, api_host, method):
    idp = str(uuid4())
    gid = str(uuid4())
    base = f"/scim/v2/inbound/{idp}/Groups"
    url = base if method == "post" else f"{base}/{gid}"
    fn = getattr(client, method)
    kwargs: dict = {"headers": {"host": api_host}}
    if method != "delete":
        kwargs["json"] = {"displayName": "x"}
    resp = fn(url, **kwargs)
    assert resp.status_code == 401
    assert resp.json()["status"] == "401"
