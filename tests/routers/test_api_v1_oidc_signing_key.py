"""Tests for the OIDC signing-key management API endpoints.

Covers the operator surface at /api/v1/oidc/signing-key: status read
(admin), rotation (super_admin), and manual retired-key cleanup
(super_admin). Service behaviour is unit-tested in
tests/services/oidc/test_keys.py; these tests verify the HTTP layer:
auth wiring, request/response shapes, and ServiceError translation.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
import settings
from schemas.oidc import OIDCSigningKeyRotationResult, OIDCSigningKeyStatus
from services.exceptions import ValidationError

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def api_user():
    """Mock super_admin user for signing-key endpoints."""
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


def _sample_status(**overrides):
    defaults = {
        "kid": "kid-active",
        "algorithm": "RS256",
        "created_at": datetime.now(UTC),
        "previous_kid": None,
        "previous_created_at": None,
        "rotation_grace_period_ends_at": None,
        "rotation_in_progress": False,
    }
    defaults.update(overrides)
    return OIDCSigningKeyStatus(**defaults)


def _sample_rotation_result(**overrides):
    now = datetime.now(UTC)
    defaults = {
        "kid": "kid-new",
        "previous_kid": "kid-old",
        "rotated_at": now,
        "grace_period_ends_at": now + timedelta(hours=24),
    }
    defaults.update(overrides)
    return OIDCSigningKeyRotationResult(**defaults)


# =============================================================================
# GET /api/v1/oidc/signing-key
# =============================================================================


class TestGetStatus:
    def test_returns_status(self, client, api_user, api_host, override_api_auth):
        override_api_auth(api_user, level="admin")
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.get_signing_key_status"
        ) as mock_status:
            mock_status.return_value = _sample_status()
            resp = client.get("/api/v1/oidc/signing-key", headers={"Host": api_host})

        assert resp.status_code == 200
        body = resp.json()
        assert body["kid"] == "kid-active"
        assert body["algorithm"] == "RS256"
        assert body["rotation_in_progress"] is False
        # The service received the authenticated requesting user.
        ru = mock_status.call_args.args[0]
        assert ru["id"] == str(api_user["id"])
        assert ru["tenant_id"] == str(api_user["tenant_id"])

    def test_reports_rotation_in_progress(self, client, api_user, api_host, override_api_auth):
        override_api_auth(api_user, level="admin")
        grace_end = datetime.now(UTC) + timedelta(hours=12)
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.get_signing_key_status"
        ) as mock_status:
            mock_status.return_value = _sample_status(
                previous_kid="kid-old",
                previous_created_at=datetime.now(UTC) - timedelta(days=30),
                rotation_grace_period_ends_at=grace_end,
                rotation_in_progress=True,
            )
            resp = client.get("/api/v1/oidc/signing-key", headers={"Host": api_host})

        assert resp.status_code == 200
        body = resp.json()
        assert body["previous_kid"] == "kid-old"
        assert body["rotation_in_progress"] is True

    def test_requires_auth(self, client, api_host):
        resp = client.get("/api/v1/oidc/signing-key", headers={"Host": api_host})
        assert resp.status_code in (401, 403)


# =============================================================================
# POST /api/v1/oidc/signing-key/rotate
# =============================================================================


class TestRotate:
    def test_rotate_with_default_grace(self, client, api_user, api_host, override_api_auth):
        override_api_auth(api_user, level="super_admin")
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.rotate_signing_key"
        ) as mock_rotate:
            mock_rotate.return_value = _sample_rotation_result()
            resp = client.post("/api/v1/oidc/signing-key/rotate", headers={"Host": api_host})

        assert resp.status_code == 200
        body = resp.json()
        assert body["kid"] == "kid-new"
        assert body["previous_kid"] == "kid-old"
        assert mock_rotate.call_args.kwargs["grace_period_hours"] == 24

    def test_rotate_with_custom_grace(self, client, api_user, api_host, override_api_auth):
        override_api_auth(api_user, level="super_admin")
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.rotate_signing_key"
        ) as mock_rotate:
            mock_rotate.return_value = _sample_rotation_result()
            resp = client.post(
                "/api/v1/oidc/signing-key/rotate",
                headers={"Host": api_host},
                json={"grace_period_hours": 72},
            )

        assert resp.status_code == 200
        assert mock_rotate.call_args.kwargs["grace_period_hours"] == 72

    def test_rotate_rejects_out_of_bounds_grace(
        self, client, api_user, api_host, override_api_auth
    ):
        override_api_auth(api_user, level="super_admin")
        for bad in (0, 721):
            resp = client.post(
                "/api/v1/oidc/signing-key/rotate",
                headers={"Host": api_host},
                json={"grace_period_hours": bad},
            )
            assert resp.status_code == 422

    def test_rotate_in_progress_translates_to_400(
        self, client, api_user, api_host, override_api_auth
    ):
        override_api_auth(api_user, level="super_admin")
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.rotate_signing_key"
        ) as mock_rotate:
            mock_rotate.side_effect = ValidationError(
                message="Signing-key rotation already in progress",
                code="oidc_signing_key_rotation_in_progress",
            )
            resp = client.post("/api/v1/oidc/signing-key/rotate", headers={"Host": api_host})

        assert resp.status_code == 400

    def test_rotate_requires_auth(self, client, api_host):
        resp = client.post("/api/v1/oidc/signing-key/rotate", headers={"Host": api_host})
        assert resp.status_code in (401, 403)


# =============================================================================
# POST /api/v1/oidc/signing-key/cleanup
# =============================================================================


class TestCleanup:
    def test_cleanup_returns_true_when_cleared(self, client, api_user, api_host, override_api_auth):
        override_api_auth(api_user, level="super_admin")
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.force_cleanup_previous_signing_key"
        ) as mock_cleanup:
            mock_cleanup.return_value = True
            resp = client.post("/api/v1/oidc/signing-key/cleanup", headers={"Host": api_host})

        assert resp.status_code == 200
        assert resp.json() == {"cleaned_up": True}

    def test_cleanup_returns_false_when_nothing_to_clear(
        self, client, api_user, api_host, override_api_auth
    ):
        override_api_auth(api_user, level="super_admin")
        with patch(
            "routers.api.v1.oidc_signing_keys.oidc_keys_service.force_cleanup_previous_signing_key"
        ) as mock_cleanup:
            mock_cleanup.return_value = False
            resp = client.post("/api/v1/oidc/signing-key/cleanup", headers={"Host": api_host})

        assert resp.status_code == 200
        assert resp.json() == {"cleaned_up": False}

    def test_cleanup_requires_auth(self, client, api_host):
        resp = client.post("/api/v1/oidc/signing-key/cleanup", headers={"Host": api_host})
        assert resp.status_code in (401, 403)
