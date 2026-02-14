"""Tenant branding service: logo upload, validation, settings management."""

import re
import struct

import database
from schemas.branding import BrandingSettings, BrandingSettingsUpdate, LogoMode, LogoSlot
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser

# Maximum logo file size: 256 KB
MAX_LOGO_SIZE = 256 * 1024

# PNG magic bytes
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

# SVG detection: starts with XML declaration or <svg tag
_SVG_PATTERN = re.compile(r"^\s*(<\?xml[^?]*\?>)?\s*<svg\b", re.IGNORECASE | re.DOTALL)

# SVG viewBox pattern for extracting dimensions
_VIEWBOX_PATTERN = re.compile(r'viewBox\s*=\s*["\'](\S+)\s+(\S+)\s+(\S+)\s+(\S+)["\']')


def _detect_mime_type(data: bytes, filename: str | None = None) -> str | None:
    """Detect MIME type from magic bytes and optional filename extension.

    Returns 'image/png', 'image/svg+xml', or None for unsupported formats.
    """
    if data[:8] == _PNG_MAGIC:
        return "image/png"

    # Try to decode as text for SVG detection
    try:
        text = data[:1024].decode("utf-8", errors="strict")
        if _SVG_PATTERN.match(text):
            return "image/svg+xml"
    except (UnicodeDecodeError, ValueError):
        pass

    # Fallback to extension
    if filename:
        lower = filename.lower()
        if lower.endswith(".png"):
            return "image/png"
        if lower.endswith(".svg"):
            return "image/svg+xml"

    return None


def _validate_png(data: bytes) -> None:
    """Validate PNG is square and at least 48x48 by parsing the IHDR chunk."""
    if len(data) < 24:
        raise ValidationError(
            message="PNG file is too small to be valid",
            code="invalid_png",
        )

    # IHDR chunk starts at byte 16 (after 8-byte magic + 4 length + 4 'IHDR')
    # Width at offset 16, Height at offset 20 (4 bytes each, big-endian)
    width = struct.unpack(">I", data[16:20])[0]
    height = struct.unpack(">I", data[20:24])[0]

    if width != height:
        raise ValidationError(
            message=f"Logo must be square. Got {width}x{height}",
            code="logo_not_square",
            field="file",
        )

    if width < 48:
        raise ValidationError(
            message=f"Logo must be at least 48x48 pixels. Got {width}x{height}",
            code="logo_too_small",
            field="file",
        )


def _validate_svg_square(data: bytes) -> None:
    """Validate SVG has a square viewBox."""
    try:
        text = data.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise ValidationError(
            message="SVG file contains invalid characters",
            code="invalid_svg",
        )

    match = _VIEWBOX_PATTERN.search(text)
    if not match:
        # No viewBox attribute; accept it (browser will render as-is)
        return

    try:
        vb_width = float(match.group(3))
        vb_height = float(match.group(4))
    except (ValueError, IndexError):
        return  # Malformed viewBox, let the browser handle it

    if abs(vb_width - vb_height) > 0.01:
        raise ValidationError(
            message=f"SVG viewBox must be square. Got {vb_width}x{vb_height}",
            code="logo_not_square",
            field="file",
        )


def _validate_logo(data: bytes, filename: str | None = None) -> str:
    """Validate logo file and return its MIME type.

    Checks file size, detects format, and validates dimensions.

    Returns:
        The detected MIME type string.

    Raises:
        ValidationError: If the file is invalid.
    """
    if len(data) > MAX_LOGO_SIZE:
        raise ValidationError(
            message=f"Logo file exceeds maximum size of {MAX_LOGO_SIZE // 1024}KB",
            code="logo_too_large",
            field="file",
        )

    if len(data) == 0:
        raise ValidationError(
            message="Logo file is empty",
            code="logo_empty",
            field="file",
        )

    mime_type = _detect_mime_type(data, filename)
    if mime_type is None:
        raise ValidationError(
            message="Unsupported image format. Use PNG or SVG",
            code="unsupported_format",
            field="file",
        )

    if mime_type == "image/png":
        _validate_png(data)
    elif mime_type == "image/svg+xml":
        _validate_svg_square(data)

    return mime_type


# =============================================================================
# CRUD Operations
# =============================================================================


def get_branding_settings(requesting_user: RequestingUser) -> BrandingSettings:
    """Get branding settings for the tenant.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    row = database.branding.get_branding(requesting_user["tenant_id"])
    if row is None:
        return BrandingSettings()

    return BrandingSettings(
        logo_mode=LogoMode(row["logo_mode"]),
        use_logo_as_favicon=row["use_logo_as_favicon"],
        has_logo_light=row["has_logo_light"],
        has_logo_dark=row["has_logo_dark"],
        logo_light_mime=row["logo_light_mime"],
        logo_dark_mime=row["logo_dark_mime"],
        updated_at=row["updated_at"],
    )


def upload_logo(
    requesting_user: RequestingUser,
    slot: LogoSlot,
    data: bytes,
    filename: str | None = None,
) -> BrandingSettings:
    """Upload a logo image for the tenant.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated admin user.
        slot: Which logo variant to upload (light or dark).
        data: Raw image bytes.
        filename: Optional original filename for format detection.

    Returns:
        Updated branding settings.
    """
    require_admin(requesting_user)

    mime_type = _validate_logo(data, filename)

    database.branding.upsert_logo(
        tenant_id=requesting_user["tenant_id"],
        tenant_id_value=requesting_user["tenant_id"],
        slot=slot.value,
        logo_data=data,
        mime_type=mime_type,
    )

    log_event(
        tenant_id=requesting_user["tenant_id"],
        actor_user_id=requesting_user["id"],
        event_type="branding_logo_uploaded",
        artifact_type="tenant_branding",
        artifact_id=requesting_user["tenant_id"],
        metadata={"slot": slot.value, "mime_type": mime_type, "size": len(data)},
    )

    return get_branding_settings(requesting_user)


def delete_logo(
    requesting_user: RequestingUser,
    slot: LogoSlot,
) -> BrandingSettings:
    """Delete a logo image for the tenant.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated admin user.
        slot: Which logo variant to delete (light or dark).

    Returns:
        Updated branding settings.
    """
    require_admin(requesting_user)

    rows = database.branding.delete_logo(
        tenant_id=requesting_user["tenant_id"],
        slot=slot.value,
    )

    if rows == 0:
        raise NotFoundError(
            message=f"No {slot.value} logo to delete",
            code="logo_not_found",
        )

    log_event(
        tenant_id=requesting_user["tenant_id"],
        actor_user_id=requesting_user["id"],
        event_type="branding_logo_deleted",
        artifact_type="tenant_branding",
        artifact_id=requesting_user["tenant_id"],
        metadata={"slot": slot.value},
    )

    return get_branding_settings(requesting_user)


def update_branding_settings(
    requesting_user: RequestingUser,
    settings: BrandingSettingsUpdate,
) -> BrandingSettings:
    """Update branding display settings.

    Authorization: Requires admin role.

    Validates that switching to custom mode requires at least a light logo.
    """
    require_admin(requesting_user)

    # If switching to custom mode, verify a light logo exists
    if settings.logo_mode == LogoMode.CUSTOM:
        row = database.branding.get_branding(requesting_user["tenant_id"])
        has_light = row is not None and row["has_logo_light"]
        if not has_light:
            raise ValidationError(
                message="Upload a light logo before switching to custom mode",
                code="light_logo_required",
                field="logo_mode",
            )

    database.branding.update_branding_settings(
        tenant_id=requesting_user["tenant_id"],
        tenant_id_value=requesting_user["tenant_id"],
        logo_mode=settings.logo_mode.value,
        use_logo_as_favicon=settings.use_logo_as_favicon,
    )

    log_event(
        tenant_id=requesting_user["tenant_id"],
        actor_user_id=requesting_user["id"],
        event_type="branding_settings_updated",
        artifact_type="tenant_branding",
        artifact_id=requesting_user["tenant_id"],
        metadata={
            "logo_mode": settings.logo_mode.value,
            "use_logo_as_favicon": settings.use_logo_as_favicon,
        },
    )

    return get_branding_settings(requesting_user)


# =============================================================================
# Serving Helpers (no auth required)
# =============================================================================


def get_logo_for_serving(tenant_id: str, slot: str) -> dict | None:
    """Get logo binary data for the public serving endpoint.

    No authentication required. Used by the unauthenticated logo endpoint.

    Returns:
        Dict with logo_data, mime_type, updated_at. None if not found.
    """
    return database.branding.get_logo(tenant_id, slot)


def get_branding_for_template(tenant_id: str) -> dict:
    """Get lightweight branding metadata for template context.

    No authentication required. Called on every page load for logged-in users.

    Returns:
        Dict with logo_mode, use_logo_as_favicon, has_logo_light, has_logo_dark.
        Returns defaults (mandala mode) if no branding row exists.
    """
    row = database.branding.get_branding(tenant_id)
    if row is None:
        return {
            "logo_mode": "mandala",
            "use_logo_as_favicon": False,
            "has_logo_light": False,
            "has_logo_dark": False,
        }

    return {
        "logo_mode": row["logo_mode"],
        "use_logo_as_favicon": row["use_logo_as_favicon"],
        "has_logo_light": row["has_logo_light"],
        "has_logo_dark": row["has_logo_dark"],
    }
