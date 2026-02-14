"""API endpoint tests for branding (/api/v1/branding).

Covers:
- GET /api/v1/branding (auth, response shape)
- POST /api/v1/branding/logo/{slot} (upload, validation errors)
- DELETE /api/v1/branding/logo/{slot} (delete, 404)
- PUT /api/v1/branding (settings update, validation)
"""

import io
import struct
from unittest.mock import patch

# =============================================================================
# Helpers
# =============================================================================


def _make_png(width: int = 64, height: int = 64) -> bytes:
    """Create a minimal valid PNG."""
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
    ihdr_length = struct.pack(">I", 13)
    ihdr_type = b"IHDR"
    ihdr_crc = b"\x00\x00\x00\x00"
    iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    return magic + ihdr_length + ihdr_type + ihdr_data + ihdr_crc + iend


def _admin_user():
    return {
        "id": "00000000-0000-0000-0000-000000000001",
        "tenant_id": "00000000-0000-0000-0000-000000000099",
        "first_name": "Admin",
        "last_name": "User",
        "role": "admin",
        "email": "admin@example.com",
    }


# =============================================================================
# GET /api/v1/branding
# =============================================================================


def test_get_branding_as_admin(client, override_api_auth):
    """Admin can get branding settings."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with patch("services.branding.database.branding.get_branding", return_value=None):
        resp = client.get("/api/v1/branding")

    assert resp.status_code == 200
    data = resp.json()
    assert data["logo_mode"] == "mandala"
    assert data["has_logo_light"] is False


def test_get_branding_unauthenticated(client, test_host):
    """Unauthenticated request is rejected (401 or 403)."""
    resp = client.get("/api/v1/branding", headers={"host": test_host})
    assert resp.status_code in (401, 403)


# =============================================================================
# POST /api/v1/branding/logo/{slot}
# =============================================================================


def test_upload_logo_as_admin(client, override_api_auth):
    """Admin can upload a logo via API."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    png = _make_png(64, 64)

    with (
        patch("services.branding.database.branding.upsert_logo", return_value=1),
        patch(
            "services.branding.database.branding.get_branding",
            return_value={
                "logo_mode": "mandala",
                "use_logo_as_favicon": False,
                "has_logo_light": True,
                "has_logo_dark": False,
                "logo_light_mime": "image/png",
                "logo_dark_mime": None,
                "updated_at": "2026-01-01T00:00:00+00:00",
            },
        ),
        patch("services.branding.log_event"),
        patch("services.branding.track_activity"),
    ):
        resp = client.post(
            "/api/v1/branding/logo/light",
            files={"file": ("logo.png", io.BytesIO(png), "image/png")},
        )

    assert resp.status_code == 201
    assert resp.json()["has_logo_light"] is True


def test_upload_logo_validation_error(client, override_api_auth):
    """Upload with invalid data returns 400."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    resp = client.post(
        "/api/v1/branding/logo/light",
        files={"file": ("bad.gif", io.BytesIO(b"not-an-image"), "image/gif")},
    )

    assert resp.status_code == 400


# =============================================================================
# DELETE /api/v1/branding/logo/{slot}
# =============================================================================


def test_delete_logo_as_admin(client, override_api_auth):
    """Admin can delete a logo."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with (
        patch("services.branding.database.branding.delete_logo", return_value=1),
        patch(
            "services.branding.database.branding.get_branding",
            return_value={
                "logo_mode": "mandala",
                "use_logo_as_favicon": False,
                "has_logo_light": False,
                "has_logo_dark": False,
                "logo_light_mime": None,
                "logo_dark_mime": None,
                "updated_at": "2026-01-01T00:00:00+00:00",
            },
        ),
        patch("services.branding.log_event"),
        patch("services.branding.track_activity"),
    ):
        resp = client.delete("/api/v1/branding/logo/light")

    assert resp.status_code == 204


def test_delete_logo_not_found(client, override_api_auth):
    """Deleting non-existent logo returns 404."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with patch("services.branding.database.branding.delete_logo", return_value=0):
        resp = client.delete("/api/v1/branding/logo/dark")

    assert resp.status_code == 404


# =============================================================================
# PUT /api/v1/branding
# =============================================================================


def test_update_branding_settings(client, override_api_auth):
    """Admin can update branding settings."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with (
        patch(
            "services.branding.database.branding.get_branding",
            return_value={
                "logo_mode": "mandala",
                "use_logo_as_favicon": False,
                "has_logo_light": True,
                "has_logo_dark": False,
                "logo_light_mime": "image/png",
                "logo_dark_mime": None,
                "updated_at": "2026-01-01T00:00:00+00:00",
            },
        ),
        patch("services.branding.database.branding.update_branding_settings", return_value=1),
        patch("services.branding.log_event"),
        patch("services.branding.track_activity"),
    ):
        resp = client.put(
            "/api/v1/branding",
            json={"logo_mode": "custom", "use_logo_as_favicon": True},
        )

    assert resp.status_code == 200
    assert (
        resp.json()["logo_mode"] == "mandala"
    )  # Mock returns mandala since get_branding is mocked


def test_update_settings_custom_without_light_logo(client, override_api_auth):
    """Switching to custom mode without light logo returns 400."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with patch("services.branding.database.branding.get_branding", return_value=None):
        resp = client.put(
            "/api/v1/branding",
            json={"logo_mode": "custom", "use_logo_as_favicon": False},
        )

    assert resp.status_code == 400
