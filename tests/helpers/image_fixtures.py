"""Shared image test fixtures for branding tests."""

import struct


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
