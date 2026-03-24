"""Tests for email branding utilities."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture()
def _mock_db():
    """Provide a clean mock for database.branding throughout the test."""
    with patch("utils.email_branding.database") as mock:
        mock.branding = MagicMock()
        mock.tenants = MagicMock()
        yield mock


# =============================================================================
# get_email_branding
# =============================================================================


class TestGetEmailBranding:
    """Tests for get_email_branding()."""

    def test_returns_stored_png(self, _mock_db):
        """Pre-rasterized PNG is returned directly as a data URI."""
        png_bytes = b"\x89PNG\r\n\x1a\nfake"
        _mock_db.branding.get_email_branding.return_value = {
            "tenant_name": "Acme Corp",
            "logo_email_png": png_bytes,
        }

        from utils.email_branding import get_email_branding

        result = get_email_branding("tenant-123")

        assert result["tenant_name"] == "Acme Corp"
        assert result["logo_data_uri"] is not None
        assert result["logo_data_uri"].startswith("data:image/png;base64,")
        # Should not try to generate or store anything
        _mock_db.branding.upsert_email_logo_png.assert_not_called()

    def test_no_branding_row_generates_mandala(self, _mock_db):
        """When no branding row exists, generates mandala and stores it."""
        _mock_db.branding.get_email_branding.return_value = None
        _mock_db.tenants.get_tenant_by_id.return_value = {"name": "New Tenant"}

        fake_png = b"fake-png-data"
        with patch("utils.email_branding._generate_mandala_png", return_value=fake_png):
            from utils.email_branding import get_email_branding

            result = get_email_branding("tenant-new")

        assert result["tenant_name"] == "New Tenant"
        assert result["logo_data_uri"] is not None
        assert result["logo_data_uri"].startswith("data:image/png;base64,")
        # Should store the generated PNG for future use
        _mock_db.branding.upsert_email_logo_png.assert_called_once()

    def test_branding_row_without_png_generates_mandala(self, _mock_db):
        """Branding row exists but logo_email_png is NULL (pre-migration tenant)."""
        _mock_db.branding.get_email_branding.return_value = {
            "tenant_name": "Old Tenant",
            "logo_email_png": None,
        }

        fake_png = b"fake-png-data"
        with patch("utils.email_branding._generate_mandala_png", return_value=fake_png):
            from utils.email_branding import get_email_branding

            result = get_email_branding("tenant-old")

        assert result["tenant_name"] == "Old Tenant"
        assert result["logo_data_uri"] is not None
        _mock_db.branding.upsert_email_logo_png.assert_called_once()

    def test_conversion_failure_returns_no_logo(self, _mock_db):
        """If mandala generation fails, returns branding without logo."""
        _mock_db.branding.get_email_branding.return_value = None
        _mock_db.tenants.get_tenant_by_id.return_value = {"name": "Broken"}

        with patch("utils.email_branding._generate_mandala_png", return_value=None):
            from utils.email_branding import get_email_branding

            result = get_email_branding("tenant-broken")

        assert result["tenant_name"] == "Broken"
        assert result["logo_data_uri"] is None

    def test_default_tenant_name_when_none(self, _mock_db):
        """Uses 'WeftID' when tenant name is None."""
        _mock_db.branding.get_email_branding.return_value = None
        _mock_db.tenants.get_tenant_by_id.return_value = None

        with patch("utils.email_branding._generate_mandala_png", return_value=None):
            from utils.email_branding import get_email_branding

            result = get_email_branding("missing-tenant")

        assert result["tenant_name"] == "WeftID"

    def test_store_failure_still_returns_logo(self, _mock_db):
        """If storing the generated PNG fails, still returns the logo."""
        _mock_db.branding.get_email_branding.return_value = None
        _mock_db.tenants.get_tenant_by_id.return_value = {"name": "DB Error"}
        _mock_db.branding.upsert_email_logo_png.side_effect = Exception("DB write failed")

        fake_png = b"fake-png"
        with patch("utils.email_branding._generate_mandala_png", return_value=fake_png):
            from utils.email_branding import get_email_branding

            result = get_email_branding("tenant-db-error")

        # Should still return the logo even if storing failed
        assert result["logo_data_uri"] is not None
        assert result["tenant_name"] == "DB Error"


# =============================================================================
# Shared email layout
# =============================================================================


class TestWrapHtml:
    """Tests for the _wrap_html shared layout builder."""

    def test_wraps_with_branding(self):
        """HTML includes branded header when branding is provided."""
        from utils.email import _wrap_html

        branding = {
            "tenant_name": "Acme Corp",
            "logo_data_uri": "data:image/png;base64,AAAA",
        }
        result = _wrap_html("<p>Hello</p>", branding)

        assert "<!DOCTYPE html>" in result
        assert "Acme Corp" in result
        assert "data:image/png;base64,AAAA" in result
        assert "<p>Hello</p>" in result
        assert "WeftID by Pageloom" in result
        assert "WeftID by Pageloom" in result

    def test_wraps_without_branding(self):
        """HTML has no header when branding is None, but footer is present."""
        from utils.email import _wrap_html

        result = _wrap_html("<p>Hello</p>", None)

        assert "<!DOCTYPE html>" in result
        assert "<p>Hello</p>" in result
        assert "WeftID by Pageloom" in result
        # No header logo or tenant name
        assert "<img" not in result

    def test_branding_without_logo(self):
        """Header shows tenant name without logo when logo_data_uri is None."""
        from utils.email import _wrap_html

        branding = {"tenant_name": "No Logo Inc", "logo_data_uri": None}
        result = _wrap_html("<p>Content</p>", branding)

        assert "No Logo Inc" in result
        assert "<img" not in result

    def test_html_escapes_tenant_name(self):
        """Tenant names with HTML special chars are escaped."""
        from utils.email import _wrap_html

        branding = {
            "tenant_name": "Foo <script>alert('xss')</script>",
            "logo_data_uri": None,
        }
        result = _wrap_html("<p>Safe</p>", branding)

        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_inline_styles_no_css_classes(self):
        """Output uses inline styles, not CSS class references."""
        from utils.email import _wrap_html

        result = _wrap_html("<p>Content</p>", None)

        assert "<style>" not in result
        assert 'class="' not in result

    def test_footer_always_present(self):
        """Footer with automated message and Pageloom attribution is always present."""
        from utils.email import _wrap_html

        result = _wrap_html("<p>Content</p>", None)

        assert "automated message" in result
        assert "WeftID by Pageloom" in result


class TestWrapText:
    """Tests for the _wrap_text shared layout builder."""

    def test_wraps_with_branding(self):
        """Text includes tenant name header when branding is provided."""
        from utils.email import _wrap_text

        branding = {"tenant_name": "Acme Corp", "logo_data_uri": None}
        result = _wrap_text("Hello world.", branding)

        assert "Acme Corp" in result
        assert "Hello world." in result
        assert "WeftID by Pageloom" in result

    def test_wraps_without_branding(self):
        """Text has footer but no header when branding is None."""
        from utils.email import _wrap_text

        result = _wrap_text("Hello world.", None)

        assert "Hello world." in result
        assert "WeftID by Pageloom" in result


# =============================================================================
# Email functions with branding
# =============================================================================


class TestEmailFunctionsWithBranding:
    """Test that email functions pass branding through to the layout."""

    def test_mfa_code_with_tenant_id(self):
        """send_mfa_code_email fetches branding when tenant_id is provided."""
        from utils.email import send_mfa_code_email

        mock_branding = {"tenant_name": "Test Org", "logo_data_uri": None}
        with (
            patch("utils.email.send_email", return_value=True) as mock_send,
            patch("utils.email._get_branding", return_value=mock_branding),
        ):
            result = send_mfa_code_email("user@test.com", "123456", tenant_id="tid")

        assert result is True
        _, _, html_body, text_body = mock_send.call_args[0]
        assert "Test Org" in html_body
        assert "Test Org" in text_body
        assert "123456" in html_body

    def test_password_reset_with_tenant_id(self):
        """send_password_reset_email includes branding when tenant_id is provided."""
        from utils.email import send_password_reset_email

        mock_branding = {
            "tenant_name": "Branded Org",
            "logo_data_uri": "data:image/png;base64,ABC",
        }
        with (
            patch("utils.email.send_email", return_value=True) as mock_send,
            patch("utils.email._get_branding", return_value=mock_branding),
        ):
            result = send_password_reset_email(
                "user@test.com", "https://reset.url", tenant_id="tid"
            )

        assert result is True
        _, _, html_body, _ = mock_send.call_args[0]
        assert "Branded Org" in html_body
        assert "data:image/png;base64,ABC" in html_body
        assert "reset.url" in html_body

    def test_email_without_tenant_id_has_no_header(self):
        """Email without tenant_id still works but has no branded header."""
        from utils.email import send_mfa_code_email

        with patch("utils.email.send_email", return_value=True) as mock_send:
            result = send_mfa_code_email("user@test.com", "999999")

        assert result is True
        _, _, html_body, _ = mock_send.call_args[0]
        # No logo header
        assert "<img" not in html_body
        # Still has footer
        assert "WeftID by Pageloom" in html_body
        # Still has content
        assert "999999" in html_body

    def test_button_has_inline_white_color(self):
        """CTA buttons use inline style with explicit white color."""
        from utils.email import send_password_reset_email

        with patch("utils.email.send_email", return_value=True) as mock_send:
            send_password_reset_email("u@t.com", "https://reset.url")

        _, _, html_body, _ = mock_send.call_args[0]
        # The button <a> tag should have inline color: #ffffff
        assert "color: #ffffff" in html_body
        # Should NOT use CSS classes
        assert 'class="button"' not in html_body

    def test_hibp_breach_email_with_tenant_id(self):
        """HIBP breach notification includes branding."""
        from utils.email import send_hibp_breach_admin_notification

        mock_branding = {"tenant_name": "SecureCo", "logo_data_uri": None}
        with (
            patch("utils.email.send_email", return_value=True) as mock_send,
            patch("utils.email._get_branding", return_value=mock_branding),
        ):
            result = send_hibp_breach_admin_notification("admin@test.com", 5, tenant_id="tid")

        assert result is True
        _, _, html_body, _ = mock_send.call_args[0]
        assert "SecureCo" in html_body
        assert "5 users" in html_body


# =============================================================================
# Pre-rasterize on save
# =============================================================================


class TestPreRasterizeOnSave:
    """Tests for branding service pre-rasterization hooks."""

    def test_upload_png_light_updates_email_logo(self):
        """Uploading a PNG to the light slot stores it as email logo."""
        with (
            patch("services.branding.database") as mock_db,
            patch("services.branding.require_admin"),
            patch("services.branding.log_event"),
            patch("services.branding._validate_logo", return_value="image/png"),
            patch("services.branding._rasterize_to_png", return_value=b"png-data") as mock_rast,
            patch("services.branding.get_branding_settings"),
        ):
            from schemas.branding import LogoSlot
            from services.branding import upload_logo

            user = {"id": "u1", "tenant_id": "t1", "role": "admin", "email": "a@b.com"}
            upload_logo(user, LogoSlot.LIGHT, b"png-bytes", "logo.png")

            mock_rast.assert_called_once_with(b"png-bytes", "image/png")
            mock_db.branding.upsert_email_logo_png.assert_called_once_with(
                tenant_id="t1", tenant_id_value="t1", png_data=b"png-data"
            )

    def test_upload_dark_does_not_update_email_logo(self):
        """Uploading to the dark slot does not touch email logo."""
        with (
            patch("services.branding.database") as mock_db,
            patch("services.branding.require_admin"),
            patch("services.branding.log_event"),
            patch("services.branding._validate_logo", return_value="image/png"),
            patch("services.branding.get_branding_settings"),
        ):
            from schemas.branding import LogoSlot
            from services.branding import upload_logo

            user = {"id": "u1", "tenant_id": "t1", "role": "admin", "email": "a@b.com"}
            upload_logo(user, LogoSlot.DARK, b"png-bytes", "logo.png")

            mock_db.branding.upsert_email_logo_png.assert_not_called()

    def test_delete_light_clears_email_logo(self):
        """Deleting the light logo clears the email logo PNG."""
        with (
            patch("services.branding.database") as mock_db,
            patch("services.branding.require_admin"),
            patch("services.branding.log_event"),
            patch("services.branding.get_branding_settings"),
        ):
            mock_db.branding.delete_logo.return_value = 1

            from schemas.branding import LogoSlot
            from services.branding import delete_logo

            user = {"id": "u1", "tenant_id": "t1", "role": "admin", "email": "a@b.com"}
            delete_logo(user, LogoSlot.LIGHT)

            # Should have run the clear query
            mock_db.execute.assert_called_once()
            sql = mock_db.execute.call_args[0][1]
            assert "logo_email_png = NULL" in sql

    def test_save_mandala_updates_email_logo(self):
        """Saving a mandala rasterizes it and stores the email logo."""
        with (
            patch("services.branding.database") as mock_db,
            patch("services.branding.require_admin"),
            patch("services.branding.log_event"),
            patch(
                "services.branding.generate_mandala_svg",
                return_value=("<svg/>", "<svg/>", "<svg/>"),
            ),
            patch("services.branding._update_email_logo_png") as mock_update,
            patch("services.branding.get_branding_settings"),
        ):
            mock_db.branding.get_branding.return_value = {
                "use_logo_as_favicon": False,
                "show_title_in_nav": True,
                "group_avatar_style": "acronym",
            }

            from services.branding import save_mandala_as_logo

            user = {"id": "u1", "tenant_id": "t1", "role": "admin", "email": "a@b.com"}
            save_mandala_as_logo(user, "test-seed")

            mock_update.assert_called_once_with("t1", b"<svg/>", "image/svg+xml")


class TestRasterizeToPng:
    """Tests for _rasterize_to_png helper."""

    def test_png_passthrough(self):
        """PNG data is returned unchanged."""
        from services.branding import _rasterize_to_png

        data = b"\x89PNGfake"
        assert _rasterize_to_png(data, "image/png") == data

    def test_svg_conversion(self):
        """SVG data is converted via cairosvg."""
        try:
            import cairosvg  # noqa: F401
        except (ImportError, OSError):
            pytest.skip("libcairo not available on this host")

        from services.branding import _rasterize_to_png

        svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">'
            b'<rect width="10" height="10" fill="red"/></svg>'
        )
        result = _rasterize_to_png(svg, "image/svg+xml")

        assert result is not None
        assert result[:4] == b"\x89PNG"

    def test_unsupported_format_returns_none(self):
        """Unsupported MIME type returns None."""
        from services.branding import _rasterize_to_png

        assert _rasterize_to_png(b"data", "image/jpeg") is None

    def test_broken_svg_returns_none(self):
        """Malformed SVG returns None instead of raising."""
        from services.branding import _rasterize_to_png

        result = _rasterize_to_png(b"not an svg", "image/svg+xml")
        assert result is None
