import re
from pathlib import Path

from app.version import __version__


def test_version_is_valid_semver():
    """Version string must be a valid semver (MAJOR.MINOR.PATCH)."""
    assert re.match(r"^\d+\.\d+\.\d+$", __version__), f"Version {__version__!r} is not valid semver"


def test_version_matches_pyproject():
    """Runtime version must match the version declared in pyproject.toml."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    # Extract version = "x.y.z" from pyproject.toml
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    assert match, "Could not find version in pyproject.toml"
    assert __version__ == match.group(1)
