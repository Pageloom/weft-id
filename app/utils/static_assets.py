"""Static asset cache-busting utilities."""

import hashlib
from pathlib import Path

# Use CWD-relative "static" path, matching how main.py mounts StaticFiles.
# In Docker (WORKDIR /app) this resolves to /app/static/ (volume-mounted).
# In local dev/tests (run from project root) this resolves to ./static/.
_STATIC_DIR = Path("static")


def _compute_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:8]


def _build_cache() -> dict[str, str]:
    cache: dict[str, str] = {}
    if _STATIC_DIR.exists():
        for p in _STATIC_DIR.rglob("*"):
            if p.is_file():
                relative = p.relative_to(_STATIC_DIR).as_posix()
                cache[relative] = _compute_hash(p)
    return cache


# Computed once at import time (startup). No per-request overhead.
_hash_cache: dict[str, str] = _build_cache()


def static_url(path: str) -> str:
    """Return a versioned URL for a static asset.

    Appends ?v=<sha256-prefix> derived from file content at startup.
    Returns the plain /static/<path> URL if the file is not found.
    """
    version = _hash_cache.get(path)
    if version:
        return f"/static/{path}?v={version}"
    return f"/static/{path}"
