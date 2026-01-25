"""Tests for request context utilities."""

from utils.request_context import (
    clear_api_client_context,
    clear_request_context,
    get_api_client_context,
    get_request_context,
    is_system_context,
    set_api_client_context,
    set_request_context,
    system_context,
)


class TestRequestContext:
    """Tests for request metadata context."""

    def test_get_request_context_returns_none_by_default(self):
        """Request context should be None when not set."""
        clear_request_context()
        assert get_request_context() is None

    def test_set_and_get_request_context(self):
        """Should be able to set and retrieve request context."""
        metadata = {
            "remote_address": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "device": "Desktop Chrome",
            "session_id_hash": "abc123",
        }
        set_request_context(metadata)
        assert get_request_context() == metadata
        clear_request_context()

    def test_clear_request_context(self):
        """Should be able to clear request context."""
        set_request_context({"remote_address": "1.2.3.4"})
        clear_request_context()
        assert get_request_context() is None


class TestApiClientContext:
    """Tests for API client context."""

    def test_get_api_client_context_returns_none_by_default(self):
        """API client context should be None when not set."""
        clear_api_client_context()
        assert get_api_client_context() is None

    def test_set_and_get_api_client_context(self):
        """Should be able to set and retrieve API client context."""
        set_api_client_context(
            client_id="loom_client_abc123",
            client_name="Test App",
            client_type="normal",
        )
        context = get_api_client_context()
        assert context is not None
        assert context["client_id"] == "loom_client_abc123"
        assert context["client_name"] == "Test App"
        assert context["client_type"] == "normal"
        clear_api_client_context()

    def test_api_client_context_is_typed_dict(self):
        """API client context should match ApiClientContext structure."""
        set_api_client_context(
            client_id="test-id",
            client_name="Test",
            client_type="b2b",
        )
        context = get_api_client_context()
        # Should have exactly these keys
        assert set(context.keys()) == {"client_id", "client_name", "client_type"}
        clear_api_client_context()

    def test_clear_api_client_context(self):
        """Should be able to clear API client context."""
        set_api_client_context(
            client_id="test",
            client_name="Test",
            client_type="normal",
        )
        clear_api_client_context()
        assert get_api_client_context() is None


class TestSystemContext:
    """Tests for system context manager.

    Note: Tests run within conftest.py's autouse system_context fixture,
    so is_system_context() will always return True during tests.
    These tests verify the context manager works correctly when nested.
    """

    def test_is_system_context_true_during_tests(self):
        """System context is always True during tests (autouse fixture)."""
        # Tests run inside system_context() from conftest.py
        assert is_system_context() is True

    def test_nested_system_context_works(self):
        """Nested system context should maintain True state."""
        assert is_system_context() is True
        with system_context():
            # Still True when nested
            assert is_system_context() is True
        # Still True because outer context from conftest
        assert is_system_context() is True
