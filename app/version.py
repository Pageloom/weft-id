import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _get_version() -> str:
    """Read version from package metadata, baked-in file, or pyproject.toml."""
    # 1. Installed package metadata (poetry install)
    try:
        return version("weft-id")
    except PackageNotFoundError:
        pass

    # 2. Baked-in VERSION file (production Docker images)
    version_file = Path(__file__).parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()

    # 3. pyproject.toml (dev Docker: mounted at /pyproject.toml; local: ../pyproject.toml)
    for candidate in [
        Path("/pyproject.toml"),
        Path(__file__).resolve().parent.parent / "pyproject.toml",
    ]:
        if candidate.exists():
            match = re.search(
                r'^version\s*=\s*"([^"]+)"', candidate.read_text(), re.MULTILINE
            )
            if match:
                return match.group(1)

    return "0.0.0-unknown"


__version__: str = _get_version()
