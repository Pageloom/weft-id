"""Deterministic mandala SVG generator for tenant identity marks.

Generates a unique radial-symmetry SVG from a seed string (typically a tenant UUID).
Same seed always produces the same mandala. Uses Mulberry32 PRNG for determinism.
"""

from __future__ import annotations

import math

# Light and dark color palettes (vibrant, decorative)
_LIGHT_PALETTE = [
    "#E63946",  # red
    "#457B9D",  # steel blue
    "#2A9D8F",  # teal
    "#E9C46A",  # saffron
    "#F4A261",  # sandy brown
    "#264653",  # dark teal
    "#6A0572",  # purple
    "#1D3557",  # navy
    "#A8DADC",  # powder blue
    "#F77F00",  # orange
]


class _Mulberry32:
    """Mulberry32 PRNG. Same algorithm as the Pageloom site repo JS version."""

    def __init__(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    def next(self) -> float:
        """Return a float in [0, 1)."""
        self._state = (self._state + 0x6D2B79F5) & 0xFFFFFFFF
        t = self._state
        t = ((t ^ (t >> 15)) * (t | 1)) & 0xFFFFFFFF
        t = (t ^ ((t ^ (t >> 7)) * (t | 61))) & 0xFFFFFFFF
        t = (t ^ (t >> 14)) & 0xFFFFFFFF
        return t / 0xFFFFFFFF

    def range(self, lo: float, hi: float) -> float:
        return lo + self.next() * (hi - lo)

    def int_range(self, lo: int, hi: int) -> int:
        """Return an int in [lo, hi] inclusive."""
        return int(self.range(lo, hi + 0.999))

    def choice(self, items: list):
        return items[int(self.next() * len(items))]


def _seed_from_string(s: str) -> int:
    """Convert a string (e.g. UUID) into a 32-bit integer seed.

    XOR-folds all 32-bit chunks of the hex representation so that every
    part of the input influences the seed.
    """
    hex_str = str(s).replace("-", "")
    try:
        full = int(hex_str, 16)
    except ValueError:
        # Fallback: hash the string character by character
        h = 0
        for ch in s:
            h = ((h * 31) + ord(ch)) & 0xFFFFFFFF
        return h
    # XOR-fold all 32-bit chunks together
    seed = 0
    while full:
        seed ^= full & 0xFFFFFFFF
        full >>= 32
    return seed


def _make_petal_path(
    cx: float, cy: float, angle: float, r1: float, r2: float, spread: float
) -> str:
    """Curved petal shape using cubic bezier curves."""
    a = angle
    left = a - spread
    right = a + spread
    x_tip = cx + math.cos(a) * r2
    y_tip = cy + math.sin(a) * r2
    x_base_l = cx + math.cos(left) * r1
    y_base_l = cy + math.sin(left) * r1
    x_base_r = cx + math.cos(right) * r1
    y_base_r = cy + math.sin(right) * r1
    cp_dist = r2 * 0.6
    cx1 = cx + math.cos(left) * cp_dist
    cy1 = cy + math.sin(left) * cp_dist
    cx2 = cx + math.cos(right) * cp_dist
    cy2 = cy + math.sin(right) * cp_dist
    return (
        f"M{cx:.1f},{cy:.1f} "
        f"L{x_base_l:.1f},{y_base_l:.1f} "
        f"C{cx1:.1f},{cy1:.1f} {x_tip:.1f},{y_tip:.1f} {x_tip:.1f},{y_tip:.1f} "
        f"C{x_tip:.1f},{y_tip:.1f} {cx2:.1f},{cy2:.1f} {x_base_r:.1f},{y_base_r:.1f} "
        f"Z"
    )


def _make_kite_path(
    cx: float, cy: float, angle: float, r_inner: float, r_outer: float, width: float
) -> str:
    """Diamond/kite shape."""
    left = angle - width
    right = angle + width
    r_mid = (r_inner + r_outer) * 0.5
    return (
        f"M{cx + math.cos(angle) * r_inner:.1f},{cy + math.sin(angle) * r_inner:.1f} "
        f"L{cx + math.cos(left) * r_mid:.1f},{cy + math.sin(left) * r_mid:.1f} "
        f"L{cx + math.cos(angle) * r_outer:.1f},{cy + math.sin(angle) * r_outer:.1f} "
        f"L{cx + math.cos(right) * r_mid:.1f},{cy + math.sin(right) * r_mid:.1f} "
        f"Z"
    )


def _make_diamond_path(
    cx: float, cy: float, angle: float, r_inner: float, r_outer: float, width: float
) -> str:
    """Thin diamond shape."""
    left = angle - width * 0.5
    right = angle + width * 0.5
    r_mid = (r_inner + r_outer) * 0.5
    return (
        f"M{cx + math.cos(angle) * r_inner:.1f},{cy + math.sin(angle) * r_inner:.1f} "
        f"L{cx + math.cos(left) * r_mid:.1f},{cy + math.sin(left) * r_mid:.1f} "
        f"L{cx + math.cos(angle) * r_outer:.1f},{cy + math.sin(angle) * r_outer:.1f} "
        f"L{cx + math.cos(right) * r_mid:.1f},{cy + math.sin(right) * r_mid:.1f} "
        f"Z"
    )


def _make_triangle_path(
    cx: float, cy: float, angle: float, r_inner: float, r_outer: float, width: float
) -> str:
    """Triangular petal."""
    left = angle - width
    right = angle + width
    return (
        f"M{cx + math.cos(angle) * r_outer:.1f},{cy + math.sin(angle) * r_outer:.1f} "
        f"L{cx + math.cos(left) * r_inner:.1f},{cy + math.sin(left) * r_inner:.1f} "
        f"L{cx + math.cos(right) * r_inner:.1f},{cy + math.sin(right) * r_inner:.1f} "
        f"Z"
    )


def _make_bulbous_path(
    cx: float, cy: float, angle: float, r_inner: float, r_outer: float, spread: float
) -> str:
    """Bulbous/teardrop shape using quadratic curves."""
    left = angle - spread
    right = angle + spread
    x_tip = cx + math.cos(angle) * r_outer
    y_tip = cy + math.sin(angle) * r_outer
    x_base_l = cx + math.cos(left) * r_inner
    y_base_l = cy + math.sin(left) * r_inner
    x_base_r = cx + math.cos(right) * r_inner
    y_base_r = cy + math.sin(right) * r_inner
    bulge = r_outer * 0.8
    qx_l = cx + math.cos(left) * bulge
    qy_l = cy + math.sin(left) * bulge
    qx_r = cx + math.cos(right) * bulge
    qy_r = cy + math.sin(right) * bulge
    return (
        f"M{cx:.1f},{cy:.1f} "
        f"L{x_base_l:.1f},{y_base_l:.1f} "
        f"Q{qx_l:.1f},{qy_l:.1f} {x_tip:.1f},{y_tip:.1f} "
        f"Q{qx_r:.1f},{qy_r:.1f} {x_base_r:.1f},{y_base_r:.1f} "
        f"Z"
    )


def _make_star_path(
    cx: float, cy: float, angle: float, r_inner: float, r_outer: float, width: float
) -> str:
    """Pointed star spike."""
    left = angle - width * 0.3
    right = angle + width * 0.3
    r_mid = r_inner + (r_outer - r_inner) * 0.3
    return (
        f"M{cx + math.cos(angle) * r_inner:.1f},{cy + math.sin(angle) * r_inner:.1f} "
        f"L{cx + math.cos(left) * r_mid:.1f},{cy + math.sin(left) * r_mid:.1f} "
        f"L{cx + math.cos(angle) * r_outer:.1f},{cy + math.sin(angle) * r_outer:.1f} "
        f"L{cx + math.cos(right) * r_mid:.1f},{cy + math.sin(right) * r_mid:.1f} "
        f"Z"
    )


def _make_organic_path(
    cx: float, cy: float, angle: float, r_inner: float, r_outer: float, spread: float
) -> str:
    """Organic curve shape using cubic beziers with asymmetric control points."""
    left = angle - spread
    right = angle + spread
    x_tip = cx + math.cos(angle) * r_outer
    y_tip = cy + math.sin(angle) * r_outer
    x_base_l = cx + math.cos(left) * r_inner
    y_base_l = cy + math.sin(left) * r_inner
    x_base_r = cx + math.cos(right) * r_inner
    y_base_r = cy + math.sin(right) * r_inner
    cp1_dist = r_outer * 0.9
    cp2_dist = r_outer * 0.4
    cx1 = cx + math.cos(left) * cp1_dist
    cy1 = cy + math.sin(left) * cp1_dist
    cx2 = cx + math.cos(right) * cp2_dist
    cy2 = cy + math.sin(right) * cp2_dist
    cx3 = cx + math.cos(right) * cp1_dist
    cy3 = cy + math.sin(right) * cp1_dist
    cx4 = cx + math.cos(left) * cp2_dist
    cy4 = cy + math.sin(left) * cp2_dist
    return (
        f"M{cx:.1f},{cy:.1f} "
        f"L{x_base_l:.1f},{y_base_l:.1f} "
        f"C{cx1:.1f},{cy1:.1f} {cx4:.1f},{cy4:.1f} {x_tip:.1f},{y_tip:.1f} "
        f"C{cx2:.1f},{cy2:.1f} {cx3:.1f},{cy3:.1f} {x_base_r:.1f},{y_base_r:.1f} "
        f"Z"
    )


_SHAPE_FUNCS = [
    _make_petal_path,
    _make_kite_path,
    _make_diamond_path,
    _make_triangle_path,
    _make_bulbous_path,
    _make_star_path,
    _make_organic_path,
]


def generate_mandala_svg(seed: str, size: int = 40) -> str:
    """Generate a deterministic mandala SVG string from a seed.

    Args:
        seed: A string (typically a tenant UUID) to seed the PRNG.
        size: Width and height of the rendered SVG in pixels.

    Returns:
        A complete SVG element string.
    """
    rng = _Mulberry32(_seed_from_string(seed))

    viewbox = 64
    cx = viewbox / 2
    cy = viewbox / 2

    num_petals = rng.int_range(6, 10)
    num_layers = rng.int_range(2, 3)

    # Pick colors for each layer
    colors: list[str] = []
    used: set[int] = set()
    for _ in range(num_layers):
        idx = int(rng.next() * len(_LIGHT_PALETTE))
        while idx in used and len(used) < len(_LIGHT_PALETTE):
            idx = (idx + 1) % len(_LIGHT_PALETTE)
        used.add(idx)
        colors.append(_LIGHT_PALETTE[idx])

    # Pick a center dot color
    center_idx = int(rng.next() * len(_LIGHT_PALETTE))
    center_light = _LIGHT_PALETTE[center_idx]

    # Build path elements
    paths: list[str] = []
    angle_step = (2 * math.pi) / num_petals

    for layer in range(num_layers):
        shape_idx = int(rng.next() * len(_SHAPE_FUNCS))
        shape_fn = _SHAPE_FUNCS[shape_idx]

        # Layer radius bands (inner layers are smaller)
        t = layer / max(num_layers - 1, 1)
        r_inner = 2 + t * 10
        r_outer = 12 + t * 16
        spread = rng.range(0.15, 0.45)

        # Rotation offset per layer for visual variety
        offset = rng.range(0, angle_step * 0.5)

        opacity = rng.range(0.6, 0.9)

        for i in range(num_petals):
            angle = i * angle_step + offset
            d = shape_fn(cx, cy, angle, r_inner, r_outer, spread)
            paths.append(
                f'<path d="{d}" fill="{colors[layer]}" opacity="{opacity:.2f}"/>'
            )

    # Center circle
    center_r = rng.range(2.0, 4.0)
    paths.append(f'<circle cx="{cx}" cy="{cy}" r="{center_r:.1f}" fill="{center_light}"/>')

    svg_attrs = (
        f'xmlns="http://www.w3.org/2000/svg" '
        f'width="{size}" height="{size}" '
        f'viewBox="0 0 {viewbox} {viewbox}" '
        f'role="img" aria-label="Tenant identity mark"'
    )

    mandala_paths = "".join(paths)
    light_svg = f"<svg {svg_attrs}>{mandala_paths}</svg>"

    # Dark mode: same mandala on a soft bright backdrop circle
    backdrop = f'<circle cx="{cx}" cy="{cy}" r="{viewbox / 2}" fill="#e2e8f0"/>'
    dark_svg = f"<svg {svg_attrs}>{backdrop}{mandala_paths}</svg>"

    # Favicon: single SVG with CSS media query to toggle backdrop.
    # Browsers apply prefers-color-scheme inside SVG favicons.
    favicon_style = (
        "<style>"
        f".backdrop{{display:none}}"
        f"@media(prefers-color-scheme:dark){{.backdrop{{display:block}}}}"
        "</style>"
    )
    backdrop_cls = (
        f'<circle class="backdrop" cx="{cx}" cy="{cy}" '
        f'r="{viewbox / 2}" fill="#e2e8f0"/>'
    )
    favicon_svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {viewbox} {viewbox}">'
        f"{favicon_style}{backdrop_cls}{mandala_paths}</svg>"
    )

    return light_svg, dark_svg, favicon_svg
