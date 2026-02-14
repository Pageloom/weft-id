"""Tests for branding service layer functions.

Covers:
- Logo validation (PNG, SVG, size limits, format detection)
- CRUD operations (upload, delete, get settings, update settings)
- Authorization checks
- Event logging
- Activity tracking
- Template helper
"""

import struct

import database
import pytest
from services import branding as branding_service
from services.exceptions import ForbiddenError, NotFoundError, ValidationError

# =============================================================================
# Helpers
# =============================================================================


def _make_requesting_user(user: dict, tenant_id: str, role: str | None = None):
    """Create a RequestingUser for testing."""
    return {
        "id": str(user["id"]),
        "tenant_id": str(tenant_id),
        "role": role or user["role"],
    }


def _make_png(width: int = 64, height: int = 64) -> bytes:
    """Create a minimal valid PNG with the given dimensions."""
    magic = b"\x89PNG\r\n\x1a\n"
    # IHDR: length=13, type=IHDR, width, height, bit_depth=8, color_type=2, ...
    ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
    ihdr_length = struct.pack(">I", 13)
    ihdr_type = b"IHDR"
    # CRC is not validated by our code, so we use a dummy
    ihdr_crc = b"\x00\x00\x00\x00"
    # Minimal IEND chunk
    iend = b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"
    return magic + ihdr_length + ihdr_type + ihdr_data + ihdr_crc + iend


def _make_svg(width: float = 100, height: float = 100) -> bytes:
    """Create a minimal SVG with the given viewBox dimensions."""
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}">'
        f'<rect width="{width}" height="{height}"/></svg>'
    )
    return svg.encode("utf-8")


def _verify_event_logged(tenant_id: str, event_type: str):
    """Verify an event was logged."""
    events = database.event_log.list_events(tenant_id, limit=5)
    assert any(e["event_type"] == event_type for e in events), (
        f"Expected event '{event_type}' not found in recent events"
    )


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidation:
    def test_validate_png_square(self):
        """Square PNG passes validation."""
        data = _make_png(64, 64)
        mime = branding_service._validate_logo(data)
        assert mime == "image/png"

    def test_validate_png_not_square(self):
        """Non-square PNG is rejected."""
        data = _make_png(100, 50)
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "logo_not_square"

    def test_validate_png_too_small(self):
        """PNG smaller than 48x48 is rejected."""
        data = _make_png(32, 32)
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "logo_too_small"

    def test_validate_png_too_large(self):
        """PNG exceeding 256KB is rejected."""
        data = _make_png(64, 64) + b"\x00" * (256 * 1024 + 1)
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "logo_too_large"

    def test_validate_svg_square(self):
        """Square SVG passes validation."""
        data = _make_svg(100, 100)
        mime = branding_service._validate_logo(data)
        assert mime == "image/svg+xml"

    def test_validate_svg_not_square(self):
        """Non-square SVG viewBox is rejected."""
        data = _make_svg(200, 100)
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "logo_not_square"

    def test_validate_svg_no_viewbox(self):
        """SVG without viewBox is accepted."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'
        mime = branding_service._validate_logo(data)
        assert mime == "image/svg+xml"

    def test_validate_empty_file(self):
        """Empty file is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(b"")
        assert exc_info.value.code == "logo_empty"

    def test_validate_unsupported_format(self):
        """Non-PNG/SVG file is rejected."""
        data = b"GIF89a\x01\x00\x01\x00\x80\x00\x00"
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "unsupported_format"

    def test_detect_png_by_extension(self):
        """PNG detection falls back to extension."""
        # This data starts with PNG magic, so it works by magic bytes
        data = _make_png(48, 48)
        mime = branding_service._detect_mime_type(data, "logo.png")
        assert mime == "image/png"

    def test_detect_svg_by_extension(self):
        """SVG detection falls back to extension for edge cases."""
        # Valid SVG but use filename too
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'
        mime = branding_service._detect_mime_type(data, "logo.svg")
        assert mime == "image/svg+xml"

    def test_validate_svg_rejects_script_element(self):
        """SVG with <script> is rejected."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_rejects_event_handler(self):
        """SVG with event handler attributes is rejected."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><rect onload="alert(1)"/></svg>'
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_rejects_onclick(self):
        """SVG with onclick handler is rejected."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><rect onclick="alert(1)"/></svg>'
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_rejects_javascript_href(self):
        """SVG with javascript: URL is rejected."""
        data = (
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b'<a href="javascript:alert(1)"><rect/></a></svg>'
        )
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_rejects_foreign_object(self):
        """SVG with <foreignObject> is rejected."""
        data = (
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b"<foreignObject><body>HTML</body></foreignObject></svg>"
        )
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_rejects_entity_declaration(self):
        """SVG with DOCTYPE/ENTITY (XXE) is rejected."""
        # DOCTYPE before <svg> is blocked by format detection (unsupported_format).
        # Test the content validator directly to verify the entity check works.
        data = (
            b'<?xml version="1.0"?>\n'
            b"<!DOCTYPE svg [<!ENTITY xxe 'evil'>]>\n"
            b'<svg xmlns="http://www.w3.org/2000/svg"><text>ok</text></svg>'
        )
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_svg_content(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_rejects_disallowed_element(self):
        """SVG with non-whitelisted elements is rejected."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><iframe src="evil"/></svg>'
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_logo(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_allows_safe_content(self):
        """SVG with only safe drawing primitives passes."""
        data = (
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
            b'<defs><linearGradient id="g"><stop offset="0" stop-color="red"/>'
            b"</linearGradient></defs>"
            b'<g><rect width="100" height="100" fill="url(#g)"/>'
            b'<circle cx="50" cy="50" r="20"/>'
            b'<path d="M10 10 L90 90"/></g></svg>'
        )
        mime = branding_service._validate_logo(data)
        assert mime == "image/svg+xml"

    def test_validate_svg_allows_style_element(self):
        """SVG with <style> (for CSS, not script) passes."""
        data = (
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
            b"<style>.cls{fill:red}</style>"
            b'<rect class="cls" width="100" height="100"/></svg>'
        )
        mime = branding_service._validate_logo(data)
        assert mime == "image/svg+xml"


# =============================================================================
# Get Settings Tests
# =============================================================================


class TestGetSettings:
    def test_get_settings_default(self, test_tenant, test_admin_user):
        """Returns defaults when no branding row exists."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        result = branding_service.get_branding_settings(ru)
        assert result.logo_mode == "mandala"
        assert result.has_logo_light is False
        assert result.has_logo_dark is False
        assert result.use_logo_as_favicon is False

    def test_get_settings_forbidden_for_member(self, test_tenant, test_user):
        """Members cannot access branding settings."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")
        with pytest.raises(ForbiddenError):
            branding_service.get_branding_settings(ru)


# =============================================================================
# Upload Tests
# =============================================================================


class TestUpload:
    def test_upload_light_logo_png(self, test_tenant, test_admin_user):
        """Admin can upload a PNG light logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        data = _make_png(64, 64)

        result = branding_service.upload_logo(ru, slot=branding_service.LogoSlot.LIGHT, data=data)

        assert result.has_logo_light is True
        assert result.logo_light_mime == "image/png"
        _verify_event_logged(str(test_tenant["id"]), "branding_logo_uploaded")

    def test_upload_dark_logo_svg(self, test_tenant, test_admin_user):
        """Admin can upload an SVG dark logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        data = _make_svg(100, 100)

        result = branding_service.upload_logo(ru, slot=branding_service.LogoSlot.DARK, data=data)

        assert result.has_logo_dark is True
        assert result.logo_dark_mime == "image/svg+xml"

    def test_upload_replaces_existing(self, test_tenant, test_admin_user):
        """Uploading to a slot replaces the existing logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        data1 = _make_png(48, 48)
        data2 = _make_png(96, 96)

        branding_service.upload_logo(ru, slot=branding_service.LogoSlot.LIGHT, data=data1)
        result = branding_service.upload_logo(ru, slot=branding_service.LogoSlot.LIGHT, data=data2)

        assert result.has_logo_light is True

    def test_upload_forbidden_for_member(self, test_tenant, test_user):
        """Members cannot upload logos."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")
        with pytest.raises(ForbiddenError):
            branding_service.upload_logo(
                ru, slot=branding_service.LogoSlot.LIGHT, data=_make_png(64, 64)
            )

    def test_upload_validates_format(self, test_tenant, test_admin_user):
        """Upload rejects invalid formats."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        with pytest.raises(ValidationError) as exc_info:
            branding_service.upload_logo(
                ru, slot=branding_service.LogoSlot.LIGHT, data=b"not an image"
            )
        assert exc_info.value.code == "unsupported_format"


# =============================================================================
# Delete Tests
# =============================================================================


class TestDelete:
    def test_delete_logo(self, test_tenant, test_admin_user):
        """Admin can delete a previously uploaded logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        branding_service.upload_logo(
            ru, slot=branding_service.LogoSlot.LIGHT, data=_make_png(64, 64)
        )

        result = branding_service.delete_logo(ru, slot=branding_service.LogoSlot.LIGHT)

        assert result.has_logo_light is False
        _verify_event_logged(str(test_tenant["id"]), "branding_logo_deleted")

    def test_delete_nonexistent_logo(self, test_tenant, test_admin_user):
        """Deleting a logo that doesn't exist raises NotFoundError."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        with pytest.raises(NotFoundError):
            branding_service.delete_logo(ru, slot=branding_service.LogoSlot.DARK)

    def test_delete_forbidden_for_member(self, test_tenant, test_user):
        """Members cannot delete logos."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")
        with pytest.raises(ForbiddenError):
            branding_service.delete_logo(ru, slot=branding_service.LogoSlot.LIGHT)


# =============================================================================
# Update Settings Tests
# =============================================================================


class TestUpdateSettings:
    def test_switch_to_custom_with_light_logo(self, test_tenant, test_admin_user):
        """Admin can switch to custom mode when a light logo exists."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        branding_service.upload_logo(
            ru, slot=branding_service.LogoSlot.LIGHT, data=_make_png(64, 64)
        )

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.CUSTOM, use_logo_as_favicon=True)
        result = branding_service.update_branding_settings(ru, update)

        assert result.logo_mode == "custom"
        assert result.use_logo_as_favicon is True
        _verify_event_logged(str(test_tenant["id"]), "branding_settings_updated")

    def test_switch_to_custom_without_light_logo_fails(self, test_tenant, test_admin_user):
        """Cannot switch to custom mode without uploading a light logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.CUSTOM)
        with pytest.raises(ValidationError) as exc_info:
            branding_service.update_branding_settings(ru, update)
        assert exc_info.value.code == "light_logo_required"

    def test_switch_to_mandala(self, test_tenant, test_admin_user):
        """Admin can switch back to mandala mode."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA)
        result = branding_service.update_branding_settings(ru, update)

        assert result.logo_mode == "mandala"

    def test_update_forbidden_for_member(self, test_tenant, test_user):
        """Members cannot update branding settings."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA)
        with pytest.raises(ForbiddenError):
            branding_service.update_branding_settings(ru, update)


# =============================================================================
# Serving Helper Tests
# =============================================================================


class TestServingHelpers:
    def test_get_logo_for_serving(self, test_tenant, test_admin_user):
        """Can retrieve logo binary for serving after upload."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        png_data = _make_png(64, 64)
        branding_service.upload_logo(ru, slot=branding_service.LogoSlot.LIGHT, data=png_data)

        result = branding_service.get_logo_for_serving(str(test_tenant["id"]), "light")

        assert result is not None
        assert result["logo_data"] == png_data
        assert result["mime_type"] == "image/png"

    def test_get_logo_for_serving_not_found(self, test_tenant):
        """Returns None when no logo exists."""
        result = branding_service.get_logo_for_serving(str(test_tenant["id"]), "light")
        assert result is None

    def test_get_branding_for_template_default(self, test_tenant):
        """Returns mandala defaults when no branding row."""
        result = branding_service.get_branding_for_template(str(test_tenant["id"]))
        assert result["logo_mode"] == "mandala"
        assert result["has_logo_light"] is False

    def test_get_branding_for_template_with_data(self, test_tenant, test_admin_user):
        """Returns actual branding data after upload."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        branding_service.upload_logo(
            ru, slot=branding_service.LogoSlot.LIGHT, data=_make_png(64, 64)
        )

        result = branding_service.get_branding_for_template(str(test_tenant["id"]))
        assert result["has_logo_light"] is True
        assert result["logo_mode"] == "mandala"  # Mode not changed, just uploaded
