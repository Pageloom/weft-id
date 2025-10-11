"""Tests for FastAPI dependencies."""

from dependencies import normalize_host


def test_normalize_host_basic():
    """Test normalize_host with basic hostname."""
    assert normalize_host('example.com') == 'example.com'


def test_normalize_host_with_port():
    """Test normalize_host removes port number."""
    assert normalize_host('example.com:8000') == 'example.com'


def test_normalize_host_with_trailing_dot():
    """Test normalize_host removes trailing dot."""
    assert normalize_host('example.com.') == 'example.com'


def test_normalize_host_with_uppercase():
    """Test normalize_host converts to lowercase."""
    assert normalize_host('EXAMPLE.COM') == 'example.com'


def test_normalize_host_with_none():
    """Test normalize_host handles None."""
    assert normalize_host(None) == ''


def test_normalize_host_complex():
    """Test normalize_host with complex input."""
    assert normalize_host('EXAMPLE.COM.:8080') == 'example.com'
