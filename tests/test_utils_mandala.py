"""Tests for mandala SVG generator."""

import re

from app.utils.mandala import generate_mandala_svg


def test_deterministic_same_seed():
    """Same seed always produces the same SVGs."""
    seed = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    result1 = generate_mandala_svg(seed)
    result2 = generate_mandala_svg(seed)
    assert result1 == result2


def test_different_seeds_produce_different_svgs():
    """Different seeds produce different SVGs."""
    light1, _, _ = generate_mandala_svg("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    light2, _, _ = generate_mandala_svg("11111111-2222-3333-4444-555555555555")
    assert light1 != light2


def test_returns_tuple_of_three_svgs():
    """Returns a (light_svg, dark_svg, favicon_svg) tuple."""
    result = generate_mandala_svg("test-seed")
    assert isinstance(result, tuple)
    assert len(result) == 3
    light, dark, favicon = result
    assert "<svg" in light
    assert "<svg" in dark
    assert "<svg" in favicon


def test_light_svg_structure():
    """Light SVG contains valid structure."""
    light, _, _ = generate_mandala_svg("deadbeef-1234-5678-9abc-def012345678")
    assert light.startswith("<svg")
    assert light.endswith("</svg>")
    assert 'xmlns="http://www.w3.org/2000/svg"' in light


def test_dark_svg_has_backdrop_circle():
    """Dark SVG includes a backdrop circle for contrast."""
    _, dark, _ = generate_mandala_svg("deadbeef-1234-5678-9abc-def012345678")
    assert 'fill="#e2e8f0"' in dark


def test_light_svg_has_no_backdrop():
    """Light SVG does not include a backdrop circle."""
    light, _, _ = generate_mandala_svg("deadbeef-1234-5678-9abc-def012345678")
    assert 'fill="#e2e8f0"' not in light


def test_output_contains_path_elements():
    """Both SVGs contain path elements for the mandala shapes."""
    light, dark, _ = generate_mandala_svg("deadbeef-1234-5678-9abc-def012345678")
    light_paths = re.findall(r"<path ", light)
    dark_paths = re.findall(r"<path ", dark)
    # 3 layers * 5 petals = 15 paths minimum
    assert len(light_paths) >= 15
    # Dark has the same paths
    assert len(dark_paths) == len(light_paths)


def test_output_contains_center_circle():
    """Both SVGs contain a center circle."""
    light, dark, _ = generate_mandala_svg("deadbeef-1234-5678-9abc-def012345678")
    assert len(re.findall(r"<circle ", light)) == 1
    # Dark has backdrop + center = 2
    assert len(re.findall(r"<circle ", dark)) == 2


def test_size_parameter():
    """Size parameter controls SVG dimensions."""
    light_s, _, _ = generate_mandala_svg("test-seed", size=24)
    light_l, _, _ = generate_mandala_svg("test-seed", size=48)
    assert 'width="24"' in light_s
    assert 'height="24"' in light_s
    assert 'width="48"' in light_l
    assert 'height="48"' in light_l


def test_default_size():
    """Default size is 40."""
    light, _, _ = generate_mandala_svg("test-seed")
    assert 'width="40"' in light
    assert 'height="40"' in light


def test_viewbox_is_64():
    """ViewBox is 0 0 64 64."""
    light, _, _ = generate_mandala_svg("test-seed")
    assert 'viewBox="0 0 64 64"' in light


def test_accessibility_label():
    """SVG includes accessible role and label."""
    light, dark, _ = generate_mandala_svg("test-seed")
    for svg in (light, dark):
        assert 'role="img"' in svg
        assert 'aria-label="Tenant identity mark"' in svg


def test_non_uuid_seed():
    """Generator works with non-UUID strings as seeds."""
    light, dark, _ = generate_mandala_svg("some-arbitrary-string")
    assert "<svg" in light
    assert "</svg>" in dark


def test_many_uuids_produce_variety():
    """A set of different UUIDs produces a variety of distinct SVGs."""
    uuids = [f"{i:08x}-0000-0000-0000-000000000000" for i in range(20)]
    svgs = {generate_mandala_svg(u)[0] for u in uuids}
    # All 20 should be unique
    assert len(svgs) == 20


def test_output_contains_color_values():
    """Output includes hex color fill values."""
    light, _, _ = generate_mandala_svg("test-seed")
    color_fills = re.findall(r'fill="#[0-9A-Fa-f]{6}"', light)
    assert len(color_fills) > 0


def test_favicon_svg_has_media_query():
    """Favicon SVG uses CSS media query for dark mode backdrop."""
    _, _, favicon = generate_mandala_svg("test-seed")
    assert "prefers-color-scheme:dark" in favicon
    assert 'class="backdrop"' in favicon


def test_favicon_svg_has_no_fixed_dimensions():
    """Favicon SVG uses viewBox only (no width/height) for browser scaling."""
    _, _, favicon = generate_mandala_svg("test-seed")
    assert 'viewBox="0 0 64 64"' in favicon
    assert "width=" not in favicon
    assert "height=" not in favicon
