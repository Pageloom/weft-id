"""API endpoint tests for branding (/api/v1/branding).

Covers:
- GET /api/v1/branding (auth, response shape)
- POST /api/v1/branding/logo/{slot} (upload, validation errors)
- DELETE /api/v1/branding/logo/{slot} (delete, 404)
- PUT /api/v1/branding (settings update, validation)
"""

import io
from unittest.mock import patch

from helpers.image_fixtures import _make_png


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
    assert data["tenant_name"] is None
    assert data["show_title_in_nav"] is True


def test_get_branding_unauthenticated(client):
    """Unauthenticated request is rejected (401 or 403)."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "fake-tenant-id"
    resp = client.get("/api/v1/branding")
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
                "tenant_name": None,
                "show_title_in_nav": True,
                "has_logo_light": True,
                "has_logo_dark": False,
                "logo_light_mime": "image/png",
                "logo_dark_mime": None,
                "group_avatar_style": "acronym",
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
                "tenant_name": None,
                "show_title_in_nav": True,
                "has_logo_light": False,
                "has_logo_dark": False,
                "logo_light_mime": None,
                "logo_dark_mime": None,
                "group_avatar_style": "acronym",
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
                "tenant_name": None,
                "show_title_in_nav": True,
                "has_logo_light": True,
                "has_logo_dark": False,
                "logo_light_mime": "image/png",
                "logo_dark_mime": None,
                "group_avatar_style": "acronym",
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


def test_update_branding_settings_with_tenant_name(client, override_api_auth):
    """Admin can update branding settings with tenant name."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with (
        patch(
            "services.branding.database.branding.get_branding",
            return_value={
                "logo_mode": "mandala",
                "use_logo_as_favicon": False,
                "tenant_name": "My App",
                "show_title_in_nav": False,
                "has_logo_light": False,
                "has_logo_dark": False,
                "logo_light_mime": None,
                "logo_dark_mime": None,
                "group_avatar_style": "acronym",
                "updated_at": "2026-01-01T00:00:00+00:00",
            },
        ),
        patch("services.branding.database.branding.update_branding_settings", return_value=1),
        patch("services.branding.database.tenants.update_tenant_name", return_value=1),
        patch("services.branding.log_event"),
        patch("services.branding.track_activity"),
    ):
        resp = client.put(
            "/api/v1/branding",
            json={
                "logo_mode": "mandala",
                "use_logo_as_favicon": False,
                "tenant_name": "My App",
                "show_title_in_nav": False,
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["tenant_name"] == "My App"
    assert data["show_title_in_nav"] is False


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


# =============================================================================
# POST /api/v1/branding/mandala/randomize
# =============================================================================


def test_randomize_mandala_as_admin(client, override_api_auth):
    """Admin can randomize a mandala."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    resp = client.post("/api/v1/branding/mandala/randomize")

    assert resp.status_code == 200
    data = resp.json()
    assert "seed" in data
    assert "<svg" in data["light_svg"]
    assert "<svg" in data["dark_svg"]


def test_randomize_mandala_unauthenticated(client):
    """Unauthenticated request is rejected."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "fake-tenant-id"
    resp = client.post("/api/v1/branding/mandala/randomize")
    assert resp.status_code in (401, 403)


# =============================================================================
# POST /api/v1/branding/mandala/save
# =============================================================================


def test_save_mandala_as_admin(client, override_api_auth):
    """Admin can save a mandala as custom logo."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    with (
        patch("services.branding.database.branding.upsert_logo", return_value=1),
        patch(
            "services.branding.database.branding.get_branding",
            return_value={
                "logo_mode": "custom",
                "use_logo_as_favicon": False,
                "tenant_name": None,
                "show_title_in_nav": True,
                "has_logo_light": True,
                "has_logo_dark": True,
                "logo_light_mime": "image/svg+xml",
                "logo_dark_mime": "image/svg+xml",
                "group_avatar_style": "acronym",
                "updated_at": "2026-01-01T00:00:00+00:00",
            },
        ),
        patch("services.branding.database.branding.update_branding_settings", return_value=1),
        patch("services.branding.log_event"),
        patch("services.branding.track_activity"),
    ):
        resp = client.post(
            "/api/v1/branding/mandala/save",
            json={"seed": "test-seed-123"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["logo_mode"] == "custom"
    assert data["has_logo_light"] is True
    assert data["has_logo_dark"] is True


def test_save_mandala_unauthenticated(client):
    """Unauthenticated request is rejected."""
    from dependencies import get_tenant_id_from_request
    from main import app

    app.dependency_overrides[get_tenant_id_from_request] = lambda: "fake-tenant-id"
    resp = client.post(
        "/api/v1/branding/mandala/save",
        json={"seed": "test"},
    )
    assert resp.status_code in (401, 403)


def test_save_mandala_empty_seed_rejected(client, override_api_auth):
    """Empty seed is rejected by schema validation."""
    user = _admin_user()
    override_api_auth(user, level="admin")

    resp = client.post(
        "/api/v1/branding/mandala/save",
        json={"seed": ""},
    )
    assert resp.status_code == 422


# =============================================================================
# GET /branding/group-logo/{group_id}
# =============================================================================


def test_serve_group_logo_returns_200(client, override_api_auth):
    """Uploaded group logo is served with correct content type and ETag."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    png = _make_png(64, 64)
    group_id = "00000000-0000-0000-0000-000000000042"

    with patch(
        "services.branding.database.branding.get_group_logo",
        return_value={
            "logo_data": png,
            "logo_mime": "image/png",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    ):
        resp = client.get(f"/branding/group-logo/{group_id}")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert "ETag" in resp.headers
    assert resp.content == png


def test_serve_group_logo_not_found(client):
    """Returns 404 when no logo exists for the group."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    group_id = "00000000-0000-0000-0000-000000000042"

    with patch(
        "services.branding.database.branding.get_group_logo",
        return_value=None,
    ):
        resp = client.get(f"/branding/group-logo/{group_id}")

    assert resp.status_code == 404


def test_serve_group_logo_etag_304(client):
    """Returns 304 when ETag matches."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    group_id = "00000000-0000-0000-0000-000000000042"
    updated_at = "2026-01-01T00:00:00+00:00"
    png = _make_png(64, 64)

    logo_data = {
        "logo_data": png,
        "logo_mime": "image/png",
        "updated_at": updated_at,
    }

    # Get ETag from first request, then use it
    with patch(
        "services.branding.database.branding.get_group_logo",
        return_value=logo_data,
    ):
        first_resp = client.get(f"/branding/group-logo/{group_id}")

    assert first_resp.status_code == 200
    etag = first_resp.headers["ETag"]

    with patch(
        "services.branding.database.branding.get_group_logo",
        return_value=logo_data,
    ):
        resp = client.get(
            f"/branding/group-logo/{group_id}",
            headers={"if-none-match": etag},
        )

    assert resp.status_code == 304


# =============================================================================
# POST /api/v1/service-providers/{sp_id}/logo
# =============================================================================


def _super_admin_user():
    return {
        "id": "00000000-0000-0000-0000-000000000001",
        "tenant_id": "00000000-0000-0000-0000-000000000099",
        "first_name": "Super",
        "last_name": "Admin",
        "role": "super_admin",
        "email": "super@example.com",
    }


def test_upload_sp_logo_as_super_admin(client, override_api_auth):
    """Super admin can upload an SP logo via API."""
    user = _super_admin_user()
    override_api_auth(user, level="super_admin")

    png = _make_png(64, 64)

    with (
        patch("services.branding.database.branding.upsert_sp_logo"),
        patch("services.branding.log_event"),
    ):
        resp = client.post(
            "/api/v1/service-providers/00000000-0000-0000-0000-000000000042/logo",
            files={"file": ("logo.png", io.BytesIO(png), "image/png")},
        )

    assert resp.status_code == 201


def test_upload_sp_logo_validation_error(client, override_api_auth):
    """Upload with invalid data returns 400."""
    user = _super_admin_user()
    override_api_auth(user, level="super_admin")

    resp = client.post(
        "/api/v1/service-providers/00000000-0000-0000-0000-000000000042/logo",
        files={"file": ("bad.gif", io.BytesIO(b"not-an-image"), "image/gif")},
    )

    assert resp.status_code == 400


# =============================================================================
# DELETE /api/v1/service-providers/{sp_id}/logo
# =============================================================================


def test_delete_sp_logo_as_super_admin(client, override_api_auth):
    """Super admin can delete an SP logo."""
    user = _super_admin_user()
    override_api_auth(user, level="super_admin")

    with (
        patch("services.branding.database.branding.delete_sp_logo", return_value=1),
        patch("services.branding.log_event"),
    ):
        resp = client.delete("/api/v1/service-providers/00000000-0000-0000-0000-000000000042/logo")

    assert resp.status_code == 204


def test_delete_sp_logo_not_found(client, override_api_auth):
    """Deleting non-existent SP logo returns 404."""
    user = _super_admin_user()
    override_api_auth(user, level="super_admin")

    with patch("services.branding.database.branding.delete_sp_logo", return_value=0):
        resp = client.delete("/api/v1/service-providers/00000000-0000-0000-0000-000000000042/logo")

    assert resp.status_code == 404


# =============================================================================
# GET /branding/sp-logo/{sp_id}
# =============================================================================


def test_serve_sp_logo_returns_200(client):
    """Uploaded SP logo is served with correct content type and ETag."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    png = _make_png(64, 64)
    sp_id = "00000000-0000-0000-0000-000000000042"

    with patch(
        "services.branding.database.branding.get_sp_logo",
        return_value={
            "logo_data": png,
            "logo_mime": "image/png",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    ):
        resp = client.get(f"/branding/sp-logo/{sp_id}")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert "ETag" in resp.headers
    assert resp.content == png


def test_serve_sp_logo_not_found(client):
    """Returns 404 when no logo exists for the SP."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    sp_id = "00000000-0000-0000-0000-000000000042"

    with patch(
        "services.branding.database.branding.get_sp_logo",
        return_value=None,
    ):
        resp = client.get(f"/branding/sp-logo/{sp_id}")

    assert resp.status_code == 404


def test_serve_sp_logo_etag_304(client):
    """Returns 304 when ETag matches."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    sp_id = "00000000-0000-0000-0000-000000000042"
    png = _make_png(64, 64)

    logo_data = {
        "logo_data": png,
        "logo_mime": "image/png",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }

    # Get ETag from first request
    with patch(
        "services.branding.database.branding.get_sp_logo",
        return_value=logo_data,
    ):
        first_resp = client.get(f"/branding/sp-logo/{sp_id}")

    assert first_resp.status_code == 200
    etag = first_resp.headers["ETag"]

    # Second request with If-None-Match
    with patch(
        "services.branding.database.branding.get_sp_logo",
        return_value=logo_data,
    ):
        resp = client.get(
            f"/branding/sp-logo/{sp_id}",
            headers={"if-none-match": etag},
        )

    assert resp.status_code == 304


def test_serve_sp_logo_cache_headers(client):
    """SP logo response includes correct cache headers."""
    from dependencies import get_tenant_id_from_request
    from main import app

    tenant_id = "00000000-0000-0000-0000-000000000099"
    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id

    png = _make_png(64, 64)
    sp_id = "00000000-0000-0000-0000-000000000042"

    with patch(
        "services.branding.database.branding.get_sp_logo",
        return_value={
            "logo_data": png,
            "logo_mime": "image/png",
            "updated_at": "2026-01-01T00:00:00+00:00",
        },
    ):
        resp = client.get(f"/branding/sp-logo/{sp_id}")

    assert "max-age=3600" in resp.headers["cache-control"]
    assert "must-revalidate" in resp.headers["cache-control"]
    assert "public" in resp.headers["cache-control"]
