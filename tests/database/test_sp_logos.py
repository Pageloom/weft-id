"""Tests for SP logo database operations.

Integration tests that verify sp_logos table operations,
including the LEFT JOIN in list/get queries.
"""

import database
import database.branding
import database.service_providers


def _create_sp(tenant_id, user_id, name="Logo Test SP"):
    """Helper to create a service provider with sensible defaults."""
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def _make_png_bytes():
    """Minimal valid PNG bytes for testing."""
    import struct

    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">II", 64, 64) + b"\x08\x02\x00\x00\x00"
    ihdr_length = struct.pack(">I", 13)
    ihdr_crc = b"\x00\x00\x00\x00"
    iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    return magic + ihdr_length + b"IHDR" + ihdr_data + ihdr_crc + iend


# -- upsert_sp_logo / get_sp_logo -------------------------------------------


def test_upsert_and_get_sp_logo(test_tenant, test_user):
    """Upserted logo can be retrieved."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    png = _make_png_bytes()

    database.branding.upsert_sp_logo(
        tenant_id=test_tenant["id"],
        sp_id=str(sp["id"]),
        logo_data=png,
        mime_type="image/png",
    )

    result = database.branding.get_sp_logo(test_tenant["id"], str(sp["id"]))
    assert result is not None
    assert result["logo_data"] == png
    assert result["logo_mime"] == "image/png"
    assert result["updated_at"] is not None


def test_upsert_sp_logo_replaces_existing(test_tenant, test_user):
    """Second upsert replaces the first."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    png = _make_png_bytes()
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect/></svg>'

    database.branding.upsert_sp_logo(test_tenant["id"], str(sp["id"]), png, "image/png")
    database.branding.upsert_sp_logo(test_tenant["id"], str(sp["id"]), svg, "image/svg+xml")

    result = database.branding.get_sp_logo(test_tenant["id"], str(sp["id"]))
    assert result is not None
    assert result["logo_mime"] == "image/svg+xml"
    assert result["logo_data"] == svg


def test_get_sp_logo_not_found(test_tenant, test_user):
    """Returns None when SP has no logo."""
    sp = _create_sp(test_tenant["id"], test_user["id"])

    result = database.branding.get_sp_logo(test_tenant["id"], str(sp["id"]))
    assert result is None


# -- delete_sp_logo ----------------------------------------------------------


def test_delete_sp_logo(test_tenant, test_user):
    """Delete returns 1 and removes the logo."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    png = _make_png_bytes()

    database.branding.upsert_sp_logo(test_tenant["id"], str(sp["id"]), png, "image/png")

    rows = database.branding.delete_sp_logo(test_tenant["id"], str(sp["id"]))
    assert rows == 1

    result = database.branding.get_sp_logo(test_tenant["id"], str(sp["id"]))
    assert result is None


def test_delete_sp_logo_not_found(test_tenant, test_user):
    """Delete returns 0 when no logo exists."""
    sp = _create_sp(test_tenant["id"], test_user["id"])

    rows = database.branding.delete_sp_logo(test_tenant["id"], str(sp["id"]))
    assert rows == 0


# -- CASCADE on SP delete ----------------------------------------------------


def test_sp_logo_deleted_on_sp_delete(test_tenant, test_user):
    """Logo row is cascade-deleted when the SP is deleted."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    png = _make_png_bytes()

    database.branding.upsert_sp_logo(test_tenant["id"], str(sp["id"]), png, "image/png")

    database.service_providers.delete_service_provider(test_tenant["id"], str(sp["id"]))

    result = database.branding.get_sp_logo(test_tenant["id"], str(sp["id"]))
    assert result is None


# -- has_logo in list/get queries --------------------------------------------


def test_list_sps_includes_has_logo(test_tenant, test_user):
    """list_service_providers includes has_logo and logo_updated_at."""
    sp = _create_sp(test_tenant["id"], test_user["id"], name="Logo List SP")

    # Before logo upload
    sps = database.service_providers.list_service_providers(test_tenant["id"])
    sp_row = next(s for s in sps if s["id"] == sp["id"])
    assert sp_row["has_logo"] is False
    assert sp_row["logo_updated_at"] is None

    # After logo upload
    png = _make_png_bytes()
    database.branding.upsert_sp_logo(test_tenant["id"], str(sp["id"]), png, "image/png")

    sps = database.service_providers.list_service_providers(test_tenant["id"])
    sp_row = next(s for s in sps if s["id"] == sp["id"])
    assert sp_row["has_logo"] is True
    assert sp_row["logo_updated_at"] is not None


def test_get_sp_includes_has_logo(test_tenant, test_user):
    """get_service_provider includes has_logo and logo_updated_at."""
    sp = _create_sp(test_tenant["id"], test_user["id"])

    fetched = database.service_providers.get_service_provider(test_tenant["id"], str(sp["id"]))
    assert fetched["has_logo"] is False

    png = _make_png_bytes()
    database.branding.upsert_sp_logo(test_tenant["id"], str(sp["id"]), png, "image/png")

    fetched = database.service_providers.get_service_provider(test_tenant["id"], str(sp["id"]))
    assert fetched["has_logo"] is True
    assert fetched["logo_updated_at"] is not None
