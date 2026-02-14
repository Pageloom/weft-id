"""Tests for public branding endpoint (/branding/logo/{slot}).

Covers:
- Logo serving (200 response, correct content-type)
- 404 when no logo exists
- ETag/304 conditional requests
- Cache headers
"""

import struct
from datetime import UTC, datetime
from unittest.mock import patch


def _make_png(width: int = 64, height: int = 64) -> bytes:
    """Create a minimal valid PNG."""
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
    ihdr_length = struct.pack(">I", 13)
    ihdr_type = b"IHDR"
    ihdr_crc = b"\x00\x00\x00\x00"
    iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    return magic + ihdr_length + ihdr_type + ihdr_data + ihdr_crc + iend


def test_serve_logo_success(client, test_host):
    """Serves logo with correct content-type and cache headers."""
    png_data = _make_png(64, 64)
    updated = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

    with patch(
        "services.branding.database.branding.get_logo",
        return_value={
            "logo_data": png_data,
            "mime_type": "image/png",
            "updated_at": updated,
        },
    ):
        resp = client.get("/branding/logo/light", headers={"host": test_host})

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert "max-age=3600" in resp.headers["cache-control"]
    assert "ETag" in resp.headers
    assert resp.content == png_data


def test_serve_logo_not_found(client, test_host):
    """Returns 404 when no logo exists for the slot."""
    with patch("services.branding.database.branding.get_logo", return_value=None):
        resp = client.get("/branding/logo/dark", headers={"host": test_host})

    assert resp.status_code == 404


def test_serve_logo_etag_304(client, test_host):
    """Returns 304 when If-None-Match matches the ETag."""

    png_data = _make_png(64, 64)
    updated = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

    # First request to get the ETag
    with patch(
        "services.branding.database.branding.get_logo",
        return_value={
            "logo_data": png_data,
            "mime_type": "image/png",
            "updated_at": updated,
        },
    ):
        # First request to capture the ETag
        resp = client.get("/branding/logo/light", headers={"host": test_host})

    assert resp.status_code == 200
    etag = resp.headers["ETag"]

    # Second request with If-None-Match
    with patch(
        "services.branding.database.branding.get_logo",
        return_value={
            "logo_data": png_data,
            "mime_type": "image/png",
            "updated_at": updated,
        },
    ):
        resp2 = client.get(
            "/branding/logo/light",
            headers={"host": test_host, "if-none-match": etag},
        )

    assert resp2.status_code == 304


def test_serve_logo_invalid_slot(client, test_host):
    """Invalid slot value returns 422."""
    resp = client.get("/branding/logo/invalid", headers={"host": test_host})
    assert resp.status_code == 422


def test_serve_logo_svg(client, test_host):
    """SVG logos are served with correct content-type."""
    svg_data = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect/></svg>'
    updated = datetime(2026, 2, 1, 0, 0, 0, tzinfo=UTC)

    with patch(
        "services.branding.database.branding.get_logo",
        return_value={
            "logo_data": svg_data,
            "mime_type": "image/svg+xml",
            "updated_at": updated,
        },
    ):
        resp = client.get("/branding/logo/light", headers={"host": test_host})

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"


def test_serve_logo_must_revalidate(client, test_host):
    """Cache-Control includes must-revalidate."""
    png_data = _make_png(64, 64)
    updated = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)

    with patch(
        "services.branding.database.branding.get_logo",
        return_value={
            "logo_data": png_data,
            "mime_type": "image/png",
            "updated_at": updated,
        },
    ):
        resp = client.get("/branding/logo/light", headers={"host": test_host})

    assert "must-revalidate" in resp.headers["cache-control"]
    assert "public" in resp.headers["cache-control"]
