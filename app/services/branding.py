"""Tenant branding service: logo upload, validation, settings management."""

import re
import struct
import uuid

import database
from defusedxml import ElementTree as DefusedET
from schemas.branding import (
    BrandingSettings,
    BrandingSettingsUpdate,
    GroupAvatarStyle,
    LogoMode,
    LogoSlot,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.mandala import generate_mandala_svg

# Maximum logo file size: 256 KB
MAX_LOGO_SIZE = 256 * 1024

# Maximum site title length
MAX_SITE_TITLE_LENGTH = 30

# Default site title when none is configured
DEFAULT_SITE_TITLE = "WeftId"

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


# Allowed SVG element local names (drawing primitives and structure)
_SVG_SAFE_ELEMENTS = frozenset(
    {
        "svg",
        "g",
        "defs",
        "symbol",
        "use",
        "title",
        "desc",
        "path",
        "rect",
        "circle",
        "ellipse",
        "line",
        "polyline",
        "polygon",
        "text",
        "tspan",
        "textPath",
        "clipPath",
        "mask",
        "pattern",
        "marker",
        "linearGradient",
        "radialGradient",
        "stop",
        "image",
        "style",
    }
)

# Event handler attribute prefixes that must be rejected
_EVENT_HANDLER_PREFIX = "on"

# Attributes that can reference external resources
_DANGEROUS_ATTR_VALUES_RE = re.compile(r"javascript:|data:text/html", re.IGNORECASE)


def _validate_svg_content(data: bytes) -> None:
    """Validate SVG content is safe (no scripts, event handlers, or external entities).

    Rejects SVGs containing dangerous content rather than silently stripping it,
    so the admin knows exactly what needs to be fixed.
    """
    try:
        text = data.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise ValidationError(
            message="SVG file contains invalid characters",
            code="invalid_svg",
        )

    # Reject XML entity declarations (XXE prevention)
    if "<!ENTITY" in text or "<!DOCTYPE" in text:
        raise ValidationError(
            message="SVG must not contain DOCTYPE or ENTITY declarations",
            code="svg_unsafe_content",
            field="file",
        )

    try:
        root = DefusedET.fromstring(text)
    except DefusedET.ParseError:
        raise ValidationError(
            message="SVG contains invalid XML",
            code="invalid_svg",
            field="file",
        )

    for elem in root.iter():
        # Strip namespace prefix to get the local name
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

        if tag == "script":
            raise ValidationError(
                message="SVG must not contain <script> elements",
                code="svg_unsafe_content",
                field="file",
            )

        if tag == "foreignObject":
            raise ValidationError(
                message="SVG must not contain <foreignObject> elements",
                code="svg_unsafe_content",
                field="file",
            )

        if tag not in _SVG_SAFE_ELEMENTS:
            raise ValidationError(
                message=f"SVG contains disallowed element: <{tag}>",
                code="svg_unsafe_content",
                field="file",
            )

        for attr_name, attr_value in elem.attrib.items():
            # Strip namespace from attribute name
            local_attr = attr_name.split("}")[-1] if "}" in attr_name else attr_name

            if local_attr.lower().startswith(_EVENT_HANDLER_PREFIX):
                raise ValidationError(
                    message=f"SVG must not contain event handler attributes: {local_attr}",
                    code="svg_unsafe_content",
                    field="file",
                )

            if _DANGEROUS_ATTR_VALUES_RE.search(attr_value):
                raise ValidationError(
                    message="SVG must not contain javascript: or data:text/html references",
                    code="svg_unsafe_content",
                    field="file",
                )


def _validate_svg_square(data: bytes) -> None:
    """Validate SVG has a square viewBox and safe content."""
    _validate_svg_content(data)

    text = data.decode("utf-8")  # Already validated as valid UTF-8 above
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

    # If custom mode is set but the light logo was deleted, fall back to mandala
    # to avoid an unsubmittable form state.
    logo_mode = LogoMode(row["logo_mode"])
    if logo_mode == LogoMode.CUSTOM and not row["has_logo_light"]:
        logo_mode = LogoMode.MANDALA

    return BrandingSettings(
        logo_mode=logo_mode,
        use_logo_as_favicon=row["use_logo_as_favicon"],
        site_title=row["site_title"],
        show_title_in_nav=row["show_title_in_nav"],
        has_logo_light=row["has_logo_light"],
        has_logo_dark=row["has_logo_dark"],
        logo_light_mime=row["logo_light_mime"],
        logo_dark_mime=row["logo_dark_mime"],
        group_avatar_style=GroupAvatarStyle(row["group_avatar_style"]),
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

    current_row = database.branding.get_branding(requesting_user["tenant_id"])

    # If switching to custom mode, verify a light logo exists
    if settings.logo_mode == LogoMode.CUSTOM:
        has_light = current_row is not None and current_row["has_logo_light"]
        if not has_light:
            raise ValidationError(
                message="Upload a light logo before switching to custom mode",
                code="light_logo_required",
                field="logo_mode",
            )

    # Normalize site_title: strip whitespace, treat empty/whitespace-only as None
    site_title = settings.site_title
    if site_title is not None:
        site_title = site_title.strip()
        if not site_title:
            site_title = None

    # Validate title length
    if site_title is not None and len(site_title) > MAX_SITE_TITLE_LENGTH:
        raise ValidationError(
            message=f"Site title must be {MAX_SITE_TITLE_LENGTH} characters or fewer",
            code="site_title_too_long",
            field="site_title",
        )

    database.branding.update_branding_settings(
        tenant_id=requesting_user["tenant_id"],
        tenant_id_value=requesting_user["tenant_id"],
        logo_mode=settings.logo_mode.value,
        use_logo_as_favicon=settings.use_logo_as_favicon,
        site_title=site_title,
        show_title_in_nav=settings.show_title_in_nav,
        group_avatar_style=settings.group_avatar_style.value,
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
            "site_title": site_title,
            "show_title_in_nav": settings.show_title_in_nav,
        },
    )

    return get_branding_settings(requesting_user)


# =============================================================================
# Mandala Randomize & Save
# =============================================================================


def randomize_mandala(requesting_user: RequestingUser) -> dict:
    """Generate a random mandala for preview.

    Authorization: Requires admin role.

    Returns:
        Dict with seed, light_svg, dark_svg.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    require_admin(requesting_user)

    seed = str(uuid.uuid4())
    light_svg, dark_svg, _favicon_svg = generate_mandala_svg(seed, size=160)

    return {
        "seed": seed,
        "light_svg": light_svg,
        "dark_svg": dark_svg,
    }


def save_mandala_as_logo(requesting_user: RequestingUser, seed: str) -> BrandingSettings:
    """Save a mandala as the tenant's custom logo.

    Authorization: Requires admin role.

    Generates SVGs at nav-bar size (40px), stores both light and dark variants,
    and switches the tenant to custom logo mode.
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    light_svg, dark_svg, _favicon_svg = generate_mandala_svg(seed, size=40)
    light_bytes = light_svg.encode("utf-8")
    dark_bytes = dark_svg.encode("utf-8")
    mime = "image/svg+xml"

    # Upsert both logo slots
    database.branding.upsert_logo(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        slot="light",
        logo_data=light_bytes,
        mime_type=mime,
    )
    database.branding.upsert_logo(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        slot="dark",
        logo_data=dark_bytes,
        mime_type=mime,
    )

    # Read current settings to preserve existing values
    row = database.branding.get_branding(tenant_id)
    use_favicon = row["use_logo_as_favicon"] if row else False
    site_title = row["site_title"] if row else None
    show_title = row["show_title_in_nav"] if row else True
    group_avatar_style = row["group_avatar_style"] if row else "acronym"

    # Switch to custom mode
    database.branding.update_branding_settings(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        logo_mode="custom",
        use_logo_as_favicon=use_favicon,
        site_title=site_title,
        show_title_in_nav=show_title,
        group_avatar_style=group_avatar_style,
    )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="branding_logo_uploaded",
        artifact_type="tenant_branding",
        artifact_id=tenant_id,
        metadata={"source": "mandala", "seed": seed},
    )

    return get_branding_settings(requesting_user)


# =============================================================================
# Group Logo Operations
# =============================================================================


def upload_group_logo(
    requesting_user: RequestingUser,
    group_id: str,
    data: bytes,
    filename: str | None = None,
) -> None:
    """Upload a custom logo for a specific group.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated admin user.
        group_id: The group UUID to attach the logo to.
        data: Raw image bytes.
        filename: Optional original filename for format detection.
    """
    require_admin(requesting_user)
    mime_type = _validate_logo(data, filename)

    database.branding.upsert_group_logo(
        tenant_id=requesting_user["tenant_id"],
        group_id=group_id,
        logo_data=data,
        mime_type=mime_type,
    )

    log_event(
        tenant_id=requesting_user["tenant_id"],
        actor_user_id=requesting_user["id"],
        event_type="group_logo_uploaded",
        artifact_type="group",
        artifact_id=group_id,
        metadata={"mime_type": mime_type, "size": len(data)},
    )


def delete_group_logo(
    requesting_user: RequestingUser,
    group_id: str,
) -> None:
    """Remove a custom logo from a group.

    Authorization: Requires admin role.

    Raises:
        NotFoundError: If no logo exists for the group.
    """
    require_admin(requesting_user)

    rows = database.branding.delete_group_logo(
        tenant_id=requesting_user["tenant_id"],
        group_id=group_id,
    )

    if rows == 0:
        raise NotFoundError(
            message="No logo found for this group",
            code="group_logo_not_found",
        )

    log_event(
        tenant_id=requesting_user["tenant_id"],
        actor_user_id=requesting_user["id"],
        event_type="group_logo_removed",
        artifact_type="group",
        artifact_id=group_id,
        metadata={},
    )


def get_group_logo_for_serving(tenant_id: str, group_id: str) -> dict | None:
    """Get group logo binary data for the public serving endpoint.

    No authentication required.

    Returns:
        Dict with logo_data, logo_mime, updated_at. None if not found.
    """
    return database.branding.get_group_logo(tenant_id, group_id)


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
            "site_title": DEFAULT_SITE_TITLE,
            "show_title_in_nav": True,
            "group_avatar_style": "acronym",
            "logo_version": 0,
        }

    return {
        "logo_mode": row["logo_mode"],
        "use_logo_as_favicon": row["use_logo_as_favicon"],
        "has_logo_light": row["has_logo_light"],
        "has_logo_dark": row["has_logo_dark"],
        "site_title": row["site_title"] or DEFAULT_SITE_TITLE,
        "show_title_in_nav": row["show_title_in_nav"],
        "group_avatar_style": row["group_avatar_style"],
        "logo_version": int(row["updated_at"].timestamp()) if row.get("updated_at") else 0,
    }
