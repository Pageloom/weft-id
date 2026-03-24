"""Email branding: fetch tenant logo and name for email headers."""

import base64
import logging
from typing import TypedDict

import database
import database.branding
import database.tenants
from services.branding import EMAIL_LOGO_HEIGHT

logger = logging.getLogger(__name__)

DEFAULT_TENANT_NAME = "WeftID"


class EmailBranding(TypedDict):
    """Branding context for email templates."""

    tenant_name: str
    logo_data_uri: str | None  # "data:image/png;base64,..." or None


def get_email_branding(tenant_id: str) -> EmailBranding:
    """Fetch tenant branding for email headers.

    Reads the pre-rasterized PNG from the database. If none exists (e.g., a
    tenant that predates the email logo feature), generates and stores the
    default mandala PNG as a one-time fallback.
    """
    row = database.branding.get_email_branding(tenant_id)

    if row is not None and row["logo_email_png"]:
        return EmailBranding(
            tenant_name=row["tenant_name"] or DEFAULT_TENANT_NAME,
            logo_data_uri=_png_to_data_uri(row["logo_email_png"]),
        )

    # One-time fallback: generate mandala PNG and store it
    tenant_name = DEFAULT_TENANT_NAME
    if row is not None:
        tenant_name = row["tenant_name"] or DEFAULT_TENANT_NAME
    else:
        tenant = database.tenants.get_tenant_by_id(tenant_id)
        if tenant:
            tenant_name = tenant["name"] or DEFAULT_TENANT_NAME

    png_data = _generate_mandala_png(tenant_id)
    if png_data is not None:
        try:
            database.branding.upsert_email_logo_png(
                tenant_id=tenant_id,
                tenant_id_value=tenant_id,
                png_data=png_data,
            )
        except Exception:
            logger.warning("Failed to store fallback email logo PNG", exc_info=True)
        return EmailBranding(
            tenant_name=tenant_name,
            logo_data_uri=_png_to_data_uri(png_data),
        )

    # Conversion failed entirely; send without logo
    return EmailBranding(tenant_name=tenant_name, logo_data_uri=None)


def _png_to_data_uri(png_data: bytes) -> str:
    """Convert PNG bytes to a base64 data URI."""
    b64 = base64.b64encode(png_data).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _generate_mandala_png(tenant_id: str) -> bytes | None:
    """Generate the default mandala SVG and rasterize to PNG."""
    try:
        import cairosvg  # type: ignore[import-untyped]
        from utils.mandala import generate_mandala_svg

        light_svg, _dark_svg, _favicon_svg = generate_mandala_svg(tenant_id)
        return cairosvg.svg2png(  # type: ignore[no-any-return]
            bytestring=light_svg.encode("utf-8"),
            output_height=EMAIL_LOGO_HEIGHT,
        )
    except Exception:
        logger.warning("Failed to generate mandala PNG for email", exc_info=True)
        return None
