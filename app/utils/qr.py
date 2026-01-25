"""QR code generation utilities.

Provides local QR code generation to avoid sending sensitive data to third-party APIs.
"""

import base64
from io import BytesIO

import qrcode
from qrcode.image.pil import PilImage


def generate_qr_code_base64(data: str, box_size: int = 10, border: int = 4) -> str:
    """
    Generate a QR code as a base64-encoded data URL.

    This function creates a QR code image in memory and returns it as a base64-encoded
    data URL that can be directly embedded in HTML img tags. This eliminates the need
    to send sensitive data (like TOTP secrets) to third-party QR code generation APIs.

    Args:
        data: The data to encode in the QR code (typically a TOTP URI)
        box_size: Size of each box in pixels (default: 10)
        border: Border thickness in boxes (default: 4)

    Returns:
        A base64-encoded data URL string in the format:
        "data:image/png;base64,iVBORw0KGgoAAAANS..."

    Example:
        >>> uri = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        >>> qr_data_url = generate_qr_code_base64(uri)
        >>> # Use in template: <img src="{{ qr_data_url }}" alt="QR Code">
    """
    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,  # Auto-adjust version based on data length
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=box_size,
        border=border,
    )

    # Add data and generate the QR code
    qr.add_data(data)
    qr.make(fit=True)

    # Create PIL image
    img: PilImage = qr.make_image(fill_color="black", back_color="white")

    # Convert to PNG bytes in memory
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    # Encode as base64 and create data URL
    img_base64 = base64.b64encode(buffer.read()).decode("utf-8")
    data_url = f"data:image/png;base64,{img_base64}"

    return data_url
