"""Tests for outbound SCIM REST API endpoints.

Covers `/api/v1/service-providers/{sp_id}/scim/...`: config GET/PUT,
credentials GET/POST/rotate/DELETE, sync log GET, queue status GET, and
retry-dead-lettered POST. All endpoints require super_admin role
(promoted from admin during iteration 7b).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
import settings
from schemas.scim_admin import (
    ScimConfig,
    ScimCredential,
    ScimCredentialCreated,
    ScimCredentialList,
    ScimQueueStatus,
    ScimRetryResult,
    ScimSyncLogEntry,
    ScimSyncLogList,
)
from services.exceptions import NotFoundError, ValidationError

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


def _config(sp_id=None, **overrides):
    base = {
        "sp_id": sp_id or str(uuid4()),
        "scim_enabled": False,
        "scim_target_url": None,
        "scim_kind": "generic",
        "scim_membership_mode": "effective",
        "scim_log_retention": "3",
    }
    base.update(overrides)
    return ScimConfig(**base)


def _credential(sp_id=None, **overrides):
    base = {
        "id": str(uuid4()),
        "sp_id": sp_id or str(uuid4()),
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }
    base.update(overrides)
    return ScimCredential(**base)


# ---------------------------------------------------------------------------
# GET / PUT config
# ---------------------------------------------------------------------------


class TestGetScimConfig:
    def test_returns_config(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.get_scim_config",
            return_value=_config(sp_id=sp_id),
        ) as fn:
            resp = api_client.get(
                f"/api/v1/service-providers/{sp_id}/scim/config",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        assert resp.json()["sp_id"] == sp_id
        assert fn.called

    def test_returns_404_when_sp_missing(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.get_scim_config",
            side_effect=NotFoundError(message="missing", code="sp_not_found"),
        ):
            resp = api_client.get(
                f"/api/v1/service-providers/{sp_id}/scim/config",
                headers={"host": api_host},
            )
        assert resp.status_code == 404


class TestUpdateScimConfig:
    def test_update_success(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.update_scim_config",
            return_value=_config(
                sp_id=sp_id,
                scim_enabled=True,
                scim_target_url="https://example.com/scim",
                scim_kind="slack",
            ),
        ) as fn:
            resp = api_client.put(
                f"/api/v1/service-providers/{sp_id}/scim/config",
                headers={"host": api_host},
                json={
                    "scim_enabled": True,
                    "scim_target_url": "https://example.com/scim",
                    "scim_kind": "slack",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["scim_kind"] == "slack"
        assert fn.called

    def test_validation_error_returns_400(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.update_scim_config",
            side_effect=ValidationError(message="bad", code="scim_target_url_required"),
        ):
            resp = api_client.put(
                f"/api/v1/service-providers/{sp_id}/scim/config",
                headers={"host": api_host},
                json={"scim_enabled": True},
            )
        assert resp.status_code == 400

    def test_invalid_enum_value_rejected(self, api_client, api_host):
        sp_id = str(uuid4())
        resp = api_client.put(
            f"/api/v1/service-providers/{sp_id}/scim/config",
            headers={"host": api_host},
            json={"scim_kind": "weird"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


class TestListCredentials:
    def test_returns_list(self, api_client, api_host):
        sp_id = str(uuid4())
        items = [_credential(sp_id=sp_id)]
        with patch(
            "services.scim.admin.list_credentials",
            return_value=ScimCredentialList(items=items, total=1),
        ):
            resp = api_client.get(
                f"/api/v1/service-providers/{sp_id}/scim/credentials",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert len(body["items"]) == 1
        # Plaintext is never on the list shape.
        assert "plaintext" not in body["items"][0]


class TestCreateCredential:
    def test_creates_and_returns_plaintext(self, api_client, api_host):
        sp_id = str(uuid4())
        new_id = str(uuid4())
        with patch(
            "services.scim.admin.create_credential",
            return_value=ScimCredentialCreated(
                id=new_id,
                sp_id=sp_id,
                created_at=datetime.now(UTC),
                plaintext="secret-bearer-value",
                rotated_from_id=None,
                rotated_from_revoke_at=None,
            ),
        ):
            resp = api_client.post(
                f"/api/v1/service-providers/{sp_id}/scim/credentials",
                headers={"host": api_host},
            )
        assert resp.status_code == 201
        body = resp.json()
        assert body["plaintext"] == "secret-bearer-value"
        assert body["id"] == new_id

    def test_rate_limit_returns_429(self, api_client, api_host):
        """Over-cap create attempts return 429 with a Retry-After header.

        Mocks `ratelimit.prevent` (cache layer fails open in tests, so we
        force the raise via the same pattern other rate-limit tests use)
        to prove the endpoint translates `RateLimitError` into the
        expected 429 response.
        """
        from services.exceptions import RateLimitError

        sp_id = str(uuid4())
        with patch(
            "routers.api.v1.service_providers.ratelimit.prevent",
            side_effect=RateLimitError(
                message="rate limited", limit=10, timespan=60, retry_after=60
            ),
        ):
            resp = api_client.post(
                f"/api/v1/service-providers/{sp_id}/scim/credentials",
                headers={"host": api_host},
            )
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After") == "60"


class TestRotateCredential:
    def test_rotates_with_default_overlap(self, api_client, api_host):
        sp_id = str(uuid4())
        old_id = str(uuid4())
        new_id = str(uuid4())
        revoke_at = datetime.now(UTC)
        with patch(
            "services.scim.admin.rotate_credential",
            return_value=ScimCredentialCreated(
                id=new_id,
                sp_id=sp_id,
                created_at=datetime.now(UTC),
                plaintext="new-secret",
                rotated_from_id=old_id,
                rotated_from_revoke_at=revoke_at,
            ),
        ) as fn:
            resp = api_client.post(
                f"/api/v1/service-providers/{sp_id}/scim/credentials/{old_id}/rotate",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        assert resp.json()["rotated_from_id"] == old_id
        # Default overlap is 24h.
        assert fn.call_args.kwargs["overlap_hours"] == 24

    def test_custom_overlap_passed_through(self, api_client, api_host):
        sp_id = str(uuid4())
        old_id = str(uuid4())
        with patch(
            "services.scim.admin.rotate_credential",
            return_value=ScimCredentialCreated(
                id=str(uuid4()),
                sp_id=sp_id,
                created_at=datetime.now(UTC),
                plaintext="x",
                rotated_from_id=old_id,
                rotated_from_revoke_at=datetime.now(UTC),
            ),
        ) as fn:
            resp = api_client.post(
                f"/api/v1/service-providers/{sp_id}/scim/credentials/{old_id}/rotate?overlap_hours=48",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        assert fn.call_args.kwargs["overlap_hours"] == 48

    def test_rejects_out_of_range_overlap(self, api_client, api_host):
        sp_id = str(uuid4())
        old_id = str(uuid4())
        resp = api_client.post(
            f"/api/v1/service-providers/{sp_id}/scim/credentials/{old_id}/rotate?overlap_hours=1000",
            headers={"host": api_host},
        )
        assert resp.status_code == 422


class TestRevokeCredential:
    def test_revokes(self, api_client, api_host):
        sp_id = str(uuid4())
        cred_id = str(uuid4())
        with patch("services.scim.admin.revoke_credential", return_value=None) as fn:
            resp = api_client.delete(
                f"/api/v1/service-providers/{sp_id}/scim/credentials/{cred_id}",
                headers={"host": api_host},
            )
        assert resp.status_code == 204
        assert fn.called


# ---------------------------------------------------------------------------
# Sync log
# ---------------------------------------------------------------------------


class TestListSyncLog:
    def test_returns_paginated_list(self, api_client, api_host):
        sp_id = str(uuid4())
        entry = ScimSyncLogEntry(
            id=str(uuid4()),
            sp_id=sp_id,
            resource_type="user",
            resource_id=str(uuid4()),
            status="done",
            attempt=1,
            error=None,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )
        with patch(
            "services.scim.admin.list_sync_log",
            return_value=ScimSyncLogList(items=[entry], total=1, page=1, page_size=50),
        ) as fn:
            resp = api_client.get(
                f"/api/v1/service-providers/{sp_id}/scim/sync-log",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["page"] == 1
        assert fn.call_args.kwargs["page"] == 1
        assert fn.call_args.kwargs["page_size"] == 50

    def test_status_filter_passes_through(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.list_sync_log",
            return_value=ScimSyncLogList(items=[], total=0, page=1, page_size=50),
        ) as fn:
            api_client.get(
                f"/api/v1/service-providers/{sp_id}/scim/sync-log?status=failed",
                headers={"host": api_host},
            )
        assert fn.call_args.kwargs["status"] == "failed"


# ---------------------------------------------------------------------------
# Queue status / retry
# ---------------------------------------------------------------------------


class TestQueueStatus:
    def test_returns_counts(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.get_queue_status",
            return_value=ScimQueueStatus(sp_id=sp_id, pending=3, dead_lettered=1),
        ):
            resp = api_client.get(
                f"/api/v1/service-providers/{sp_id}/scim/queue-status",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["pending"] == 3
        assert body["dead_lettered"] == 1


class TestRetryDeadLettered:
    def test_revives_rows(self, api_client, api_host):
        sp_id = str(uuid4())
        with patch(
            "services.scim.admin.retry_dead_lettered",
            return_value=ScimRetryResult(sp_id=sp_id, revived=2),
        ):
            resp = api_client.post(
                f"/api/v1/service-providers/{sp_id}/scim/queue/retry-dead-lettered",
                headers={"host": api_host},
            )
        assert resp.status_code == 200
        assert resp.json()["revived"] == 2


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


class TestAuthorization:
    @pytest.mark.parametrize("role", ["user", "admin"])
    def test_non_super_admin_cannot_access(self, role, client, override_api_auth):
        """Both `user` and `admin` roles must be rejected.

        Iteration 7b promoted the SCIM endpoints from admin -> super_admin
        because token operations are too sensitive for the admin tier.
        """
        non_super = {
            "id": str(uuid4()),
            "tenant_id": str(uuid4()),
            "role": role,
            "email": f"{role}@test.com",
            "first_name": "X",
            "last_name": "Y",
            "tz": "UTC",
            "locale": "en_US",
        }
        override_api_auth(non_super, level=role)
        sp_id = str(uuid4())
        host = f"test.{settings.BASE_DOMAIN}"
        with patch("dependencies.database") as mock_db:
            mock_db.tenants.get_tenant_by_subdomain.return_value = {
                "id": non_super["tenant_id"],
                "subdomain": "test",
            }
            resp = client.get(
                f"/api/v1/service-providers/{sp_id}/scim/config",
                headers={"host": host},
            )
        # The route uses `require_super_admin_api`; the dep returns 401/403
        # for both `user` and `admin` roles.
        assert resp.status_code in (401, 403)
