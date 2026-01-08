"""Integration test configuration - auto-marks all tests.

Tests in this directory run against a real PostgreSQL database.
Fixtures from the parent conftest.py are automatically available.
"""

import pytest


def pytest_collection_modifyitems(items):
    """Add integration marker to all tests in this directory."""
    for item in items:
        # Only auto-mark tests in the integration directory
        if "/integration/" in str(item.fspath):
            if "integration" not in [m.name for m in item.iter_markers()]:
                item.add_marker(pytest.mark.integration)
