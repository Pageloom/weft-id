from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _get_version() -> str:
    """Read version from package metadata, falling back to a baked-in file for production images."""
    try:
        return version("weft-id")
    except PackageNotFoundError:
        version_file = Path(__file__).parent / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
        return "0.0.0-unknown"


__version__: str = _get_version()
