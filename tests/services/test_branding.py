"""Tests for branding service layer functions.

Covers:
- Logo validation (PNG, SVG, size limits, format detection)
- CRUD operations (upload, delete, get settings, update settings)
- Authorization checks
- Event logging
- Activity tracking
- Template helper
"""

import database
import pytest
from helpers.image_fixtures import _make_png, _make_svg
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

    def test_detect_png_by_extension_fallback(self):
        """Detects PNG by filename when magic bytes don't match."""
        # Random data that doesn't start with PNG magic
        data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        mime = branding_service._detect_mime_type(data, "icon.png")
        assert mime == "image/png"

    def test_detect_svg_by_extension_fallback(self):
        """Detects SVG by filename when content isn't recognized as SVG."""
        # Binary data that won't match SVG pattern
        data = b"\x00\x01\x02\x03"
        mime = branding_service._detect_mime_type(data, "logo.svg")
        assert mime == "image/svg+xml"

    def test_validate_png_data_too_short(self):
        """PNG with valid magic but truncated data is rejected."""
        # PNG magic (8 bytes) + not enough data for IHDR (need 24 total)
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 10  # Only 18 bytes total
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_png(data)
        assert exc_info.value.code == "invalid_png"

    def test_validate_svg_invalid_utf8(self):
        """SVG with invalid UTF-8 bytes is rejected."""
        data = b"\xff\xfe<svg><rect/></svg>"
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_svg_content(data)
        assert exc_info.value.code == "invalid_svg"

    def test_validate_svg_invalid_xml(self):
        """SVG with valid UTF-8 but invalid XML is rejected."""
        data = b"<svg><rect unclosed"
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_svg_content(data)
        assert exc_info.value.code == "invalid_svg"

    def test_validate_svg_javascript_in_safe_element_attr(self):
        """SVG with javascript: in a safe element's attribute is rejected."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg"><image href="javascript:alert(1)"/></svg>'
        with pytest.raises(ValidationError) as exc_info:
            branding_service._validate_svg_content(data)
        assert exc_info.value.code == "svg_unsafe_content"

    def test_validate_svg_malformed_viewbox(self):
        """SVG with non-numeric viewBox values is accepted (browser handles it)."""
        data = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 abc def"><rect/></svg>'
        # Malformed viewBox: ValueError from float(), function returns without error
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

    def test_get_settings_custom_without_logo_falls_back(self, test_tenant, test_admin_user):
        """Custom mode falls back to mandala when light logo is missing."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        # Upload a light logo, switch to custom, then delete the logo
        branding_service.upload_logo(
            ru, slot=branding_service.LogoSlot.LIGHT, data=_make_png(64, 64)
        )
        update = BrandingSettingsUpdate(logo_mode=LogoMode.CUSTOM)
        branding_service.update_branding_settings(ru, update)
        branding_service.delete_logo(ru, slot=branding_service.LogoSlot.LIGHT)

        result = branding_service.get_branding_settings(ru)
        assert result.logo_mode == "mandala"

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

    def test_set_site_title(self, test_tenant, test_admin_user):
        """Admin can set a custom site title."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA, site_title="My Company")
        result = branding_service.update_branding_settings(ru, update)

        assert result.site_title == "My Company"

    def test_site_title_too_long_rejected(self):
        """Site title exceeding 30 characters is rejected at schema level."""
        from pydantic import ValidationError as PydanticValidationError
        from schemas.branding import BrandingSettingsUpdate, LogoMode

        with pytest.raises(PydanticValidationError):
            BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA, site_title="A" * 31)

    def test_site_title_whitespace_only_treated_as_null(self, test_tenant, test_admin_user):
        """Whitespace-only title is normalized to NULL."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA, site_title="   ")
        result = branding_service.update_branding_settings(ru, update)

        assert result.site_title is None

    def test_show_title_in_nav_toggle(self, test_tenant, test_admin_user):
        """Admin can hide the title from the nav bar."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA, show_title_in_nav=False)
        result = branding_service.update_branding_settings(ru, update)

        assert result.show_title_in_nav is False

    def test_site_title_stripped(self, test_tenant, test_admin_user):
        """Site title is stripped of leading/trailing whitespace."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA, site_title="  Acme Corp  ")
        result = branding_service.update_branding_settings(ru, update)

        assert result.site_title == "Acme Corp"


# =============================================================================
# Mandala Randomize & Save Tests
# =============================================================================


class TestMandalaRandomize:
    def test_randomize_returns_seed_and_svgs(self, test_tenant, test_admin_user):
        """Randomize returns a seed and both SVG variants."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        result = branding_service.randomize_mandala(ru)

        assert "seed" in result
        assert len(result["seed"]) > 0
        assert "<svg" in result["light_svg"]
        assert "<svg" in result["dark_svg"]

    def test_randomize_produces_different_seeds(self, test_tenant, test_admin_user):
        """Each call produces a different seed."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        r1 = branding_service.randomize_mandala(ru)
        r2 = branding_service.randomize_mandala(ru)

        assert r1["seed"] != r2["seed"]

    def test_randomize_forbidden_for_member(self, test_tenant, test_user):
        """Members cannot randomize mandalas."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")
        with pytest.raises(ForbiddenError):
            branding_service.randomize_mandala(ru)


class TestMandalaSave:
    def test_save_stores_both_slots(self, test_tenant, test_admin_user):
        """Saving a mandala upserts both light and dark logo slots."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        result = branding_service.save_mandala_as_logo(ru, "test-seed-123")

        assert result.has_logo_light is True
        assert result.has_logo_dark is True
        assert result.logo_light_mime == "image/svg+xml"
        assert result.logo_dark_mime == "image/svg+xml"

    def test_save_switches_to_custom_mode(self, test_tenant, test_admin_user):
        """Saving a mandala switches the tenant to custom logo mode."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        result = branding_service.save_mandala_as_logo(ru, "test-seed-456")

        assert result.logo_mode == "custom"

    def test_save_preserves_existing_settings(self, test_tenant, test_admin_user):
        """Saving a mandala preserves existing branding settings."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        # Set some custom settings first
        update = BrandingSettingsUpdate(
            logo_mode=LogoMode.MANDALA,
            use_logo_as_favicon=True,
            site_title="My App",
            show_title_in_nav=False,
        )
        branding_service.update_branding_settings(ru, update)

        # Save mandala
        result = branding_service.save_mandala_as_logo(ru, "test-seed-789")

        assert result.logo_mode == "custom"
        assert result.site_title == "My App"
        assert result.show_title_in_nav is False

    def test_save_logs_event_with_mandala_source(self, test_tenant, test_admin_user):
        """Saving a mandala logs a branding_logo_uploaded event with source=mandala."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        branding_service.save_mandala_as_logo(ru, "test-seed-event")

        events = database.event_log.list_events(str(test_tenant["id"]), limit=5)
        logo_events = [e for e in events if e["event_type"] == "branding_logo_uploaded"]
        assert len(logo_events) >= 1
        assert logo_events[0]["metadata"]["source"] == "mandala"

    def test_save_forbidden_for_member(self, test_tenant, test_user):
        """Members cannot save mandalas."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")
        with pytest.raises(ForbiddenError):
            branding_service.save_mandala_as_logo(ru, "test-seed")


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
        assert result["site_title"] == "WeftId"
        assert result["show_title_in_nav"] is True

    def test_get_branding_for_template_with_data(self, test_tenant, test_admin_user):
        """Returns actual branding data after upload."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        branding_service.upload_logo(
            ru, slot=branding_service.LogoSlot.LIGHT, data=_make_png(64, 64)
        )

        result = branding_service.get_branding_for_template(str(test_tenant["id"]))
        assert result["has_logo_light"] is True
        assert result["logo_mode"] == "mandala"  # Mode not changed, just uploaded

    def test_get_branding_for_template_custom_title(self, test_tenant, test_admin_user):
        """Returns custom site title when set."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        update = BrandingSettingsUpdate(
            logo_mode=LogoMode.MANDALA,
            site_title="My App",
            show_title_in_nav=False,
        )
        branding_service.update_branding_settings(ru, update)

        result = branding_service.get_branding_for_template(str(test_tenant["id"]))
        assert result["site_title"] == "My App"
        assert result["show_title_in_nav"] is False

    def test_get_branding_for_template_null_title_defaults(self, test_tenant, test_admin_user):
        """NULL site_title in DB defaults to WeftId in template context."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, LogoMode

        # Set then clear the title
        update = BrandingSettingsUpdate(logo_mode=LogoMode.MANDALA, site_title=None)
        branding_service.update_branding_settings(ru, update)

        result = branding_service.get_branding_for_template(str(test_tenant["id"]))
        assert result["site_title"] == "WeftId"


# =============================================================================
# Group Logo Tests
# =============================================================================


def _create_test_group(test_tenant, test_admin_user) -> str:
    """Helper to create a test group; returns group UUID as string."""
    import database.groups

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test Logo Group",
        created_by=str(test_admin_user["id"]),
    )
    return str(result["id"])


class TestGroupLogoUpload:
    def test_upload_group_logo_success(self, test_tenant, test_admin_user):
        """Admin can upload a PNG logo for a group."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        group_id = _create_test_group(test_tenant, test_admin_user)

        branding_service.upload_group_logo(ru, group_id=group_id, data=_make_png(64, 64))

        result = branding_service.get_group_logo_for_serving(str(test_tenant["id"]), group_id)
        assert result is not None
        assert result["logo_mime"] == "image/png"
        _verify_event_logged(str(test_tenant["id"]), "group_logo_uploaded")

    def test_upload_group_logo_svg(self, test_tenant, test_admin_user):
        """Admin can upload an SVG logo for a group."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        group_id = _create_test_group(test_tenant, test_admin_user)

        branding_service.upload_group_logo(
            ru, group_id=group_id, data=_make_svg(100, 100), filename="logo.svg"
        )

        result = branding_service.get_group_logo_for_serving(str(test_tenant["id"]), group_id)
        assert result is not None
        assert result["logo_mime"] == "image/svg+xml"

    def test_upload_group_logo_replaces_existing(self, test_tenant, test_admin_user):
        """Uploading a second logo replaces the first."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        group_id = _create_test_group(test_tenant, test_admin_user)

        branding_service.upload_group_logo(ru, group_id=group_id, data=_make_png(48, 48))
        branding_service.upload_group_logo(ru, group_id=group_id, data=_make_svg(100, 100))

        result = branding_service.get_group_logo_for_serving(str(test_tenant["id"]), group_id)
        assert result is not None
        assert result["logo_mime"] == "image/svg+xml"

    def test_upload_group_logo_forbidden_for_member(self, test_tenant, test_user):
        """Non-admin cannot upload a group logo."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")

        from services.exceptions import ForbiddenError

        with pytest.raises(ForbiddenError):
            branding_service.upload_group_logo(ru, group_id="some-id", data=_make_png(64, 64))

    def test_upload_group_logo_invalid_format(self, test_tenant, test_admin_user):
        """Invalid image format is rejected."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        group_id = _create_test_group(test_tenant, test_admin_user)

        with pytest.raises(ValidationError) as exc_info:
            branding_service.upload_group_logo(ru, group_id=group_id, data=b"not-an-image")
        assert exc_info.value.code == "unsupported_format"


class TestGroupLogoDelete:
    def test_delete_group_logo_success(self, test_tenant, test_admin_user):
        """Admin can delete a group logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        group_id = _create_test_group(test_tenant, test_admin_user)

        branding_service.upload_group_logo(ru, group_id=group_id, data=_make_png(64, 64))
        branding_service.delete_group_logo(ru, group_id=group_id)

        result = branding_service.get_group_logo_for_serving(str(test_tenant["id"]), group_id)
        assert result is None
        _verify_event_logged(str(test_tenant["id"]), "group_logo_removed")

    def test_delete_group_logo_not_found(self, test_tenant, test_admin_user):
        """Deleting a non-existent logo raises NotFoundError."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        group_id = _create_test_group(test_tenant, test_admin_user)

        with pytest.raises(NotFoundError):
            branding_service.delete_group_logo(ru, group_id=group_id)

    def test_delete_group_logo_forbidden_for_member(self, test_tenant, test_user):
        """Non-admin cannot delete a group logo."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")

        from services.exceptions import ForbiddenError

        with pytest.raises(ForbiddenError):
            branding_service.delete_group_logo(ru, group_id="some-id")


# =============================================================================
# SP Logo Tests
# =============================================================================


def _create_test_sp(test_tenant, test_admin_user) -> str:
    """Helper to create a test SP; returns SP UUID as string."""
    import database.service_providers

    result = database.service_providers.create_service_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test Logo SP",
        created_by=str(test_admin_user["id"]),
    )
    return str(result["id"])


class TestSPLogoUpload:
    def test_upload_sp_logo_success(self, test_tenant, test_admin_user):
        """Admin can upload a PNG logo for an SP."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        sp_id = _create_test_sp(test_tenant, test_admin_user)

        branding_service.upload_sp_logo(ru, sp_id=sp_id, data=_make_png(64, 64))

        result = branding_service.get_sp_logo_for_serving(str(test_tenant["id"]), sp_id)
        assert result is not None
        assert result["logo_mime"] == "image/png"
        _verify_event_logged(str(test_tenant["id"]), "sp_logo_uploaded")

    def test_upload_sp_logo_svg(self, test_tenant, test_admin_user):
        """Admin can upload an SVG logo for an SP."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        sp_id = _create_test_sp(test_tenant, test_admin_user)

        branding_service.upload_sp_logo(
            ru, sp_id=sp_id, data=_make_svg(100, 100), filename="logo.svg"
        )

        result = branding_service.get_sp_logo_for_serving(str(test_tenant["id"]), sp_id)
        assert result is not None
        assert result["logo_mime"] == "image/svg+xml"

    def test_upload_sp_logo_replaces_existing(self, test_tenant, test_admin_user):
        """Uploading a second logo replaces the first."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        sp_id = _create_test_sp(test_tenant, test_admin_user)

        branding_service.upload_sp_logo(ru, sp_id=sp_id, data=_make_png(48, 48))
        branding_service.upload_sp_logo(ru, sp_id=sp_id, data=_make_svg(100, 100))

        result = branding_service.get_sp_logo_for_serving(str(test_tenant["id"]), sp_id)
        assert result is not None
        assert result["logo_mime"] == "image/svg+xml"

    def test_upload_sp_logo_forbidden_for_member(self, test_tenant, test_user):
        """Non-admin cannot upload an SP logo."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")

        from services.exceptions import ForbiddenError

        with pytest.raises(ForbiddenError):
            branding_service.upload_sp_logo(ru, sp_id="some-id", data=_make_png(64, 64))

    def test_upload_sp_logo_invalid_format(self, test_tenant, test_admin_user):
        """Invalid image format is rejected."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        sp_id = _create_test_sp(test_tenant, test_admin_user)

        with pytest.raises(ValidationError) as exc_info:
            branding_service.upload_sp_logo(ru, sp_id=sp_id, data=b"not-an-image")
        assert exc_info.value.code == "unsupported_format"


class TestSPLogoDelete:
    def test_delete_sp_logo_success(self, test_tenant, test_admin_user):
        """Admin can delete an SP logo."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        sp_id = _create_test_sp(test_tenant, test_admin_user)

        branding_service.upload_sp_logo(ru, sp_id=sp_id, data=_make_png(64, 64))
        branding_service.delete_sp_logo(ru, sp_id=sp_id)

        result = branding_service.get_sp_logo_for_serving(str(test_tenant["id"]), sp_id)
        assert result is None
        _verify_event_logged(str(test_tenant["id"]), "sp_logo_removed")

    def test_delete_sp_logo_not_found(self, test_tenant, test_admin_user):
        """Deleting a non-existent logo raises NotFoundError."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        sp_id = _create_test_sp(test_tenant, test_admin_user)

        with pytest.raises(NotFoundError):
            branding_service.delete_sp_logo(ru, sp_id=sp_id)

    def test_delete_sp_logo_forbidden_for_member(self, test_tenant, test_user):
        """Non-admin cannot delete an SP logo."""
        ru = _make_requesting_user(test_user, test_tenant["id"], "member")

        from services.exceptions import ForbiddenError

        with pytest.raises(ForbiddenError):
            branding_service.delete_sp_logo(ru, sp_id="some-id")


class TestGroupAvatarStyle:
    def test_group_avatar_style_is_acronym(self, test_tenant, test_admin_user):
        """Group avatar style is always acronym."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, GroupAvatarStyle, LogoMode

        update = BrandingSettingsUpdate(
            logo_mode=LogoMode.MANDALA, group_avatar_style=GroupAvatarStyle.ACRONYM
        )
        result = branding_service.update_branding_settings(ru, update)

        assert result.group_avatar_style == GroupAvatarStyle.ACRONYM

    def test_get_branding_for_template_includes_group_avatar_style(
        self, test_tenant, test_admin_user
    ):
        """Template context includes group_avatar_style."""
        ru = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

        from schemas.branding import BrandingSettingsUpdate, GroupAvatarStyle, LogoMode

        update = BrandingSettingsUpdate(
            logo_mode=LogoMode.MANDALA, group_avatar_style=GroupAvatarStyle.ACRONYM
        )
        branding_service.update_branding_settings(ru, update)

        result = branding_service.get_branding_for_template(str(test_tenant["id"]))
        assert result["group_avatar_style"] == "acronym"
