"""Tests for QR code generation utilities."""

import base64

from app.utils.qr import generate_qr_code_base64


def test_generate_qr_code_base64_returns_data_url():
    """Test that QR code generation returns a valid data URL."""
    data = "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    result = generate_qr_code_base64(data)

    # Should be a data URL
    assert result.startswith("data:image/png;base64,")

    # Extract base64 part
    base64_data = result.split(",", 1)[1]

    # Should be valid base64
    try:
        decoded = base64.b64decode(base64_data)
        assert len(decoded) > 0
    except Exception as e:
        raise AssertionError(f"Invalid base64 encoding: {e}")


def test_generate_qr_code_base64_creates_png_signature():
    """Test that the generated QR code is a valid PNG image."""
    data = "otpauth://totp/Test:test@test.com?secret=ABCDEFGHIJKLMNOP&issuer=Test"
    result = generate_qr_code_base64(data)

    # Extract and decode base64 data
    base64_data = result.split(",", 1)[1]
    decoded = base64.b64decode(base64_data)

    # PNG files start with signature: 89 50 4E 47 0D 0A 1A 0A
    png_signature = b"\x89PNG\r\n\x1a\n"
    assert decoded.startswith(png_signature), "Generated image is not a valid PNG"


def test_generate_qr_code_base64_with_different_data():
    """Test QR code generation with different input data."""
    data1 = "https://example.com/test"
    data2 = "Simple text"
    data3 = "otpauth://totp/App:user@domain.com?secret=SECRET123&issuer=App"

    result1 = generate_qr_code_base64(data1)
    result2 = generate_qr_code_base64(data2)
    result3 = generate_qr_code_base64(data3)

    # All should be valid data URLs
    assert result1.startswith("data:image/png;base64,")
    assert result2.startswith("data:image/png;base64,")
    assert result3.startswith("data:image/png;base64,")

    # Different data should produce different QR codes
    assert result1 != result2
    assert result2 != result3
    assert result1 != result3


def test_generate_qr_code_base64_with_custom_box_size():
    """Test QR code generation with custom box size."""
    data = "test data"

    # Generate with different box sizes
    result_small = generate_qr_code_base64(data, box_size=5)
    result_large = generate_qr_code_base64(data, box_size=15)

    # Both should be valid
    assert result_small.startswith("data:image/png;base64,")
    assert result_large.startswith("data:image/png;base64,")

    # Larger box size should produce larger image (more bytes)
    base64_small = result_small.split(",", 1)[1]
    base64_large = result_large.split(",", 1)[1]
    assert len(base64_large) > len(base64_small)


def test_generate_qr_code_base64_with_custom_border():
    """Test QR code generation with custom border."""
    data = "test data"

    # Generate with different borders
    result_no_border = generate_qr_code_base64(data, border=0)
    result_large_border = generate_qr_code_base64(data, border=10)

    # Both should be valid
    assert result_no_border.startswith("data:image/png;base64,")
    assert result_large_border.startswith("data:image/png;base64,")

    # Different borders should produce different sizes
    assert result_no_border != result_large_border


def test_generate_qr_code_base64_with_long_data():
    """Test QR code generation with longer data strings."""
    # TOTP URIs can be fairly long
    long_data = (
        "otpauth://totp/MyVeryLongApplicationName:user@verylongdomainname.example.com"
        "?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=MyVeryLongApplicationName"
        "&algorithm=SHA1&digits=6&period=30"
    )

    result = generate_qr_code_base64(long_data)

    # Should still produce valid output
    assert result.startswith("data:image/png;base64,")

    # Should be decodable
    base64_data = result.split(",", 1)[1]
    decoded = base64.b64decode(base64_data)
    assert len(decoded) > 0


def test_generate_qr_code_base64_deterministic():
    """Test that the same input produces the same output."""
    data = "otpauth://totp/Test:user@test.com?secret=TESTSECRET&issuer=Test"

    result1 = generate_qr_code_base64(data)
    result2 = generate_qr_code_base64(data)

    # Same input should produce identical output
    assert result1 == result2


def test_generate_qr_code_base64_with_special_characters():
    """Test QR code generation with special characters in data."""
    # TOTP URIs often contain URL-encoded special characters
    data = "otpauth://totp/Test%20App:user%40example.com?secret=ABC&issuer=Test%20App"

    result = generate_qr_code_base64(data)

    # Should handle special characters properly
    assert result.startswith("data:image/png;base64,")
    base64_data = result.split(",", 1)[1]
    decoded = base64.b64decode(base64_data)
    assert len(decoded) > 0
