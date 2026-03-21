import re
from pathlib import Path
from unittest.mock import patch

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


# =============================================================================
# Fallback paths (production Docker images where package isn't installed)
# =============================================================================


class TestVersionFallback:
    """Tests for _get_version fallback paths when importlib.metadata fails."""

    def test_fallback_reads_version_file(self, tmp_path):
        """When package metadata is unavailable, reads VERSION file."""
        from importlib.metadata import PackageNotFoundError

        version_file = tmp_path / "VERSION"
        version_file.write_text("2.5.1\n")

        with (
            patch(
                "app.version.version",
                side_effect=PackageNotFoundError("weft-id"),
            ),
            patch("app.version.Path") as mock_path_cls,
        ):
            mock_path_cls.return_value.__truediv__ = lambda self, other: tmp_path
            # Simpler: just patch Path(__file__).parent / "VERSION"
            mock_parent = mock_path_cls.return_value.parent
            mock_parent.__truediv__ = lambda self, name: version_file

            from app.version import _get_version

            result = _get_version()

        assert result == "2.5.1"

    def test_fallback_unknown_when_no_file(self):
        """When both package metadata and VERSION file are missing, returns unknown."""
        from importlib.metadata import PackageNotFoundError

        with (
            patch(
                "app.version.version",
                side_effect=PackageNotFoundError("weft-id"),
            ),
            patch("app.version.Path") as mock_path_cls,
        ):
            # VERSION file doesn't exist
            mock_version_file = mock_path_cls.return_value.parent.__truediv__.return_value
            mock_version_file.exists.return_value = False

            # pyproject.toml candidates don't exist either
            mock_path_cls.return_value.exists.return_value = False
            mock_path_cls.return_value.resolve.return_value.parent.parent.__truediv__.return_value.exists.return_value = False

            from app.version import _get_version

            result = _get_version()

        assert result == "0.0.0-unknown"

    def test_fallback_reads_pyproject_toml(self, tmp_path):
        """When package metadata and VERSION file are missing, reads pyproject.toml."""
        from importlib.metadata import PackageNotFoundError

        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nversion = "3.7.2"\n')

        with (
            patch(
                "app.version.version",
                side_effect=PackageNotFoundError("weft-id"),
            ),
            patch("app.version.Path") as mock_path_cls,
        ):
            # VERSION file doesn't exist
            mock_version_file = mock_path_cls.return_value.parent.__truediv__.return_value
            mock_version_file.exists.return_value = False

            # First pyproject.toml candidate (Path("/pyproject.toml")) doesn't exist
            mock_path_cls.return_value.exists.return_value = False

            # Second candidate (Path(__file__).resolve().parent.parent / "pyproject.toml") exists
            mock_pyproject = mock_path_cls.return_value.resolve.return_value.parent.parent.__truediv__.return_value
            mock_pyproject.exists.return_value = True
            mock_pyproject.read_text.return_value = pyproject.read_text()

            from app.version import _get_version

            result = _get_version()

        assert result == "3.7.2"
