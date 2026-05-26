"""Tests for the inbound SCIM Groups read endpoints.

Mirrors the Users test suite -- happy path, filter handling,
pagination, 404 behaviour. Member serialisation is exercised at the
service-layer test (`tests/services/scim/test_inbound_read.py`).
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


def _token_row(idp_id: str):
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


def test_list_groups_happy_path(client, api_host, auth_headers):
    idp = str(uuid4())
    group_payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": str(uuid4()),
        "displayName": "Engineers",
        "members": [],
        "meta": {"resourceType": "Group", "location": "https://test/.../Groups/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch(
            "services.scim.inbound_read.list_groups",
            return_value=([group_payload], 1),
        ) as svc,
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Groups",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["totalResults"] == 1
    assert body["Resources"] == [group_payload]
    # members_base_url is absolute and SCIM-path-shaped.
    members_base = svc.call_args.kwargs["members_base_url"]
    assert members_base.endswith("/Users")


def test_list_groups_display_name_filter_passed_to_service(client, api_host, auth_headers):
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.list_groups", return_value=([], 0)) as svc,
    ):
        resp = client.get(
            f'/scim/v2/inbound/{idp}/Groups?filter=displayName eq "Engineers"',
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert svc.call_args.kwargs["display_name"] == "Engineers"


def test_list_groups_invalid_filter_attribute_rejected(client, api_host, auth_headers):
    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
    ):
        resp = client.get(
            f'/scim/v2/inbound/{idp}/Groups?filter=members co "x"',
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 400
    assert resp.json()["scimType"] == "invalidFilter"


def test_get_group_returns_resource(client, api_host, auth_headers):
    idp = str(uuid4())
    gid = str(uuid4())
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": gid,
        "displayName": "Engineers",
        "members": [],
        "meta": {"resourceType": "Group", "location": "https://test/.../Groups/X"},
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.get_group", return_value=payload),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    assert resp.json() == payload


def test_get_group_returns_scim_404_when_missing(client, api_host, auth_headers):
    idp = str(uuid4())
    gid = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("services.scim.inbound_read.get_group", return_value=None),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Groups/{gid}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 404
    assert resp.json()["status"] == "404"


def test_group_member_ref_uses_users_base(client, api_host, auth_headers):
    """Member `$ref` is the absolute /Users/{id} URL of this IdP's SCIM family."""
    idp = str(uuid4())
    group_row = {
        "id": str(uuid4()),
        "name": "Engineers",
        "idp_id": idp,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    member_row = {
        "id": str(uuid4()),
        "first_name": "Amy",
        "last_name": "A",
        "email": "amy@x.test",
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=_token_row(idp)),
        patch("database.scim_inbound_tokens.touch_last_used"),
        patch("database.groups.get_group_for_idp", return_value=group_row),
        patch("database.groups.list_group_members_for_scim", return_value=[member_row]),
    ):
        resp = client.get(
            f"/scim/v2/inbound/{idp}/Groups/{group_row['id']}",
            headers={"host": api_host, **auth_headers},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["members"]) == 1
    member = body["members"][0]
    assert member["value"] == str(member_row["id"])
    assert member["type"] == "User"
    assert member["$ref"].startswith(
        f"https://test.{settings.BASE_DOMAIN}/scim/v2/inbound/{idp}/Users/"
    )
    assert member["$ref"].endswith(str(member_row["id"]))
    assert member["display"] == "Amy A"
