"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

# Add app directory to path so we can import modules
app_path = Path(__file__).parent.parent / "app"
sys.path.insert(0, str(app_path))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    from main import app

    return TestClient(app)


@pytest.fixture(scope="session", autouse=True)
def cleanup_database_pool():
    """Cleanup database pool after all tests complete."""
    yield
    # Cleanup after all tests
    import database

    database.close_pool()


@pytest.fixture
def test_subdomain():
    """Provide a test subdomain for testing."""
    return 'dev'


@pytest.fixture
def test_host(test_subdomain):
    """Provide a test host header."""
    import settings

    return f"{test_subdomain}.{settings.BASE_DOMAIN}"
