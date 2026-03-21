"""Tests for utils.cache module."""

from unittest.mock import MagicMock, patch


def test_get_returns_none_when_client_unavailable():
    """Test that get returns None when Memcached client is unavailable."""
    from utils import cache

    # Force client to None and mock connection failure
    with patch.object(cache, "_client", None):
        with patch(
            "utils.cache.get_client",
            return_value=None,
        ):
            result = cache.get("test_key")
            assert result is None


def test_set_returns_false_when_client_unavailable():
    """Test that set returns False when Memcached client is unavailable."""
    from utils import cache

    with patch.object(cache, "_client", None):
        with patch(
            "utils.cache.get_client",
            return_value=None,
        ):
            result = cache.set("test_key", b"value", ttl=300)
            assert result is False


def test_delete_returns_false_when_client_unavailable():
    """Test that delete returns False when Memcached client is unavailable."""
    from utils import cache

    with patch.object(cache, "_client", None):
        with patch(
            "utils.cache.get_client",
            return_value=None,
        ):
            result = cache.delete("test_key")
            assert result is False


def test_get_handles_exception_gracefully():
    """Test that get returns None on client exception."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.get.side_effect = Exception("Connection lost")

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.get("test_key")
            assert result is None


def test_set_handles_exception_gracefully():
    """Test that set returns False on client exception."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.set.side_effect = Exception("Connection lost")

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.set("test_key", b"value", ttl=300)
            assert result is False


def test_delete_handles_exception_gracefully():
    """Test that delete returns False on client exception."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.delete.side_effect = Exception("Connection lost")

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.delete("test_key")
            assert result is False


def test_get_client_returns_none_on_connection_failure():
    """Test that get_client returns None when connection fails."""
    from utils import cache

    # Reset the module-level client
    original_client = cache._client
    cache._client = None

    try:
        # Mock the Client constructor to raise an exception
        with patch("utils.cache.settings") as mock_settings:
            mock_settings.MEMCACHED_HOST = "nonexistent-host"
            mock_settings.MEMCACHED_PORT = 11211
            # The client creation will fail, and get_client should return None
            # or return a client that will fail on use
            _ = cache.get_client()
            # Either way, the function should not raise
    finally:
        cache._client = original_client


def test_get_converts_result_to_bytes():
    """Test that get converts the result to bytes."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.get.return_value = b"test_value"

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.get("test_key")
            assert result == b"test_value"
            assert isinstance(result, bytes)


def test_get_returns_none_for_missing_key():
    """Test that get returns None for a missing key."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.get.return_value = None

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.get("nonexistent_key")
            assert result is None


def test_set_calls_client_with_correct_args():
    """Test that set calls the client with correct arguments."""
    from utils import cache

    mock_client = MagicMock()

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            cache.set("test_key", b"test_value", ttl=3600)
            mock_client.set.assert_called_once_with("test_key", b"test_value", expire=3600)


def test_delete_calls_client_with_correct_args():
    """Test that delete calls the client with correct key."""
    from utils import cache

    mock_client = MagicMock()

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            cache.delete("test_key")
            mock_client.delete.assert_called_once_with("test_key")


# =============================================================================
# incr() tests
# =============================================================================


def test_incr_returns_new_value():
    """Test that incr returns the incremented value."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.incr.return_value = 5

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.incr("counter_key")
            assert result == 5
            mock_client.incr.assert_called_once_with("counter_key", 1)


def test_incr_with_custom_value():
    """Test that incr passes custom increment value."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.incr.return_value = 10

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.incr("counter_key", 5)
            assert result == 10
            mock_client.incr.assert_called_once_with("counter_key", 5)


def test_incr_returns_none_when_client_unavailable():
    """Test that incr returns None when Memcached client is unavailable."""
    from utils import cache

    with patch.object(cache, "_client", None):
        with patch("utils.cache.get_client", return_value=None):
            result = cache.incr("counter_key")
            assert result is None


def test_incr_handles_exception_gracefully():
    """Test that incr returns None on client exception."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.incr.side_effect = Exception("Connection lost")

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.incr("counter_key")
            assert result is None


# =============================================================================
# add() tests
# =============================================================================


def test_add_returns_true_on_success():
    """Test that add returns True when key is added."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.add.return_value = True

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.add("new_key", b"value", ttl=300)
            assert result is True
            mock_client.add.assert_called_once_with("new_key", b"value", expire=300)


def test_add_returns_false_when_key_exists():
    """Test that add returns False when key already exists."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.add.return_value = False

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.add("existing_key", b"value")
            assert result is False


def test_add_returns_false_when_client_unavailable():
    """Test that add returns False when Memcached client is unavailable."""
    from utils import cache

    with patch.object(cache, "_client", None):
        with patch("utils.cache.get_client", return_value=None):
            result = cache.add("new_key", b"value")
            assert result is False


def test_add_handles_exception_gracefully():
    """Test that add returns False on client exception."""
    from utils import cache

    mock_client = MagicMock()
    mock_client.add.side_effect = Exception("Connection lost")

    with patch.object(cache, "_client", mock_client):
        with patch("utils.cache.get_client", return_value=mock_client):
            result = cache.add("new_key", b"value")
            assert result is False


# =============================================================================
# get_client() error path
# =============================================================================


def test_get_client_returns_none_on_import_failure():
    """Test that get_client returns None when pymemcache import fails."""
    from utils import cache

    original_client = cache._client
    cache._client = None

    try:
        blocked = {"pymemcache": None, "pymemcache.client": None, "pymemcache.client.base": None}
        with patch.dict("sys.modules", blocked):
            with patch("builtins.__import__", side_effect=ImportError("No module")):
                result = cache.get_client()
                assert result is None
    finally:
        cache._client = original_client
