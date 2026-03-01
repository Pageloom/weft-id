"""Tests for static asset cache-busting utilities."""

import hashlib
from pathlib import Path
from unittest.mock import patch


def test_static_url_appends_version_for_known_file():
    """static_url returns a versioned URL for a file that exists in the hash cache."""
    from utils import static_assets as module

    fake_cache = {"css/output.css": "a1b2c3d4"}
    with patch.object(module, "_hash_cache", fake_cache):
        result = module.static_url("css/output.css")
    assert result == "/static/css/output.css?v=a1b2c3d4"


def test_static_url_returns_plain_path_for_unknown_file():
    """static_url returns the plain URL when the file is not in the hash cache."""
    from utils.static_assets import static_url

    result = static_url("does/not/exist.js")
    assert result == "/static/does/not/exist.js"


def test_static_url_same_hash_for_unchanged_file(tmp_path):
    """Hash is stable: same file content produces the same version string."""
    from utils import static_assets as module

    fake_file = tmp_path / "test.js"
    fake_file.write_bytes(b"console.log('hello');")

    fake_cache = {"test.js": module._compute_hash(fake_file)}

    with patch.object(module, "_hash_cache", fake_cache):
        result1 = module.static_url("test.js")
        result2 = module.static_url("test.js")
    assert result1 == result2


def test_static_url_different_hash_after_content_change(tmp_path):
    """Different file content produces a different version string."""
    from utils import static_assets as module

    fake_file = tmp_path / "test.js"
    fake_file.write_bytes(b"version 1")
    hash_v1 = module._compute_hash(fake_file)

    fake_file.write_bytes(b"version 2")
    hash_v2 = module._compute_hash(fake_file)

    assert hash_v1 != hash_v2


def test_compute_hash_is_sha256_prefix(tmp_path):
    """_compute_hash returns the first 8 hex chars of the SHA-256 digest."""
    from utils.static_assets import _compute_hash

    f = tmp_path / "f.txt"
    content = b"weft-id static asset"
    f.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()[:8]
    assert _compute_hash(f) == expected


def test_build_cache_empty_for_nonexistent_directory():
    """_build_cache returns an empty dict when the static directory does not exist."""
    from unittest.mock import patch

    from utils import static_assets as module

    with patch.object(module, "_STATIC_DIR", Path("/nonexistent/path/xyz")):
        cache = module._build_cache()
    assert cache == {}
