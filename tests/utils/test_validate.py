"""Tests for subdomain validation utilities."""

import pytest

from app.utils.validate import is_email_like, subdomain


@pytest.mark.parametrize(
    "value",
    [
        "alice@example.com",
        "ALICE@Example.COM",
        "  bob@sub.example.co.uk  ",
        "a+work@example.io",
        "x@y.zz",
    ],
)
def test_is_email_like_accepts_email_shaped_values(value):
    assert is_email_like(value) is True


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "alice.smith",  # bare identifier (the Okta userName case)
        "alice@",
        "@example.com",
        "alice@example",  # no dot in domain
        "alice@@example.com",  # two @
        "alice@.com",  # empty label
        "alice@example.",  # trailing dot
    ],
)
def test_is_email_like_rejects_non_email_values(value):
    assert is_email_like(value) is False


def test_valid_subdomain():
    """Test valid subdomain formats."""
    assert subdomain("example") is True
    assert subdomain("my-site") is True
    assert subdomain("test123") is True
    assert subdomain("a1-b2-c3") is True
    assert subdomain("abc") is True
    assert subdomain("a" * 63) is True  # Max length


def test_subdomain_empty():
    """Test that empty subdomain raises ValueError."""
    with pytest.raises(ValueError, match="cannot be empty"):
        subdomain("")


def test_subdomain_too_long():
    """Test that subdomain longer than 63 characters raises ValueError."""
    with pytest.raises(ValueError, match="too long"):
        subdomain("a" * 64)


def test_subdomain_invalid_characters():
    """Test that invalid characters raise ValueError."""
    with pytest.raises(ValueError, match="can only contain"):
        subdomain("test_site")

    with pytest.raises(ValueError, match="can only contain"):
        subdomain("test.site")

    with pytest.raises(ValueError, match="can only contain"):
        subdomain("test site")

    with pytest.raises(ValueError, match="can only contain"):
        subdomain("Test")  # uppercase not allowed


def test_subdomain_starts_with_hyphen():
    """Test that subdomain starting with hyphen raises ValueError."""
    with pytest.raises(ValueError, match="cannot start or end with a hyphen"):
        subdomain("-test")


def test_subdomain_ends_with_hyphen():
    """Test that subdomain ending with hyphen raises ValueError."""
    with pytest.raises(ValueError, match="cannot start or end with a hyphen"):
        subdomain("test-")


def test_subdomain_both_hyphens():
    """Test that subdomain with hyphens at both ends raises ValueError."""
    with pytest.raises(ValueError, match="cannot start or end with a hyphen"):
        subdomain("-test-")
