"""Tests for request metadata extraction and hashing utilities."""

import hashlib
from unittest.mock import MagicMock

import pytest

from app.utils import request_metadata


class TestExtractRemoteAddress:
    """Tests for extract_remote_address function."""

    def test_extract_remote_address_from_x_forwarded_for(self):
        """Verify X-Forwarded-For header is used first."""
        request = MagicMock()
        request.headers.get.side_effect = lambda key: {
            "x-forwarded-for": "203.0.113.1",
            "x-real-ip": "198.51.100.1",
        }.get(key)
        request.client.host = "192.0.2.1"

        result = request_metadata.extract_remote_address(request)

        assert result == "203.0.113.1"

    def test_extract_remote_address_from_x_real_ip(self):
        """Verify X-Real-IP fallback when X-Forwarded-For not present."""
        request = MagicMock()
        request.headers.get.side_effect = lambda key: {
            "x-real-ip": "198.51.100.1",
        }.get(key)
        request.client.host = "192.0.2.1"

        result = request_metadata.extract_remote_address(request)

        assert result == "198.51.100.1"

    def test_extract_remote_address_from_client_host(self):
        """Verify client.host fallback when headers not present."""
        request = MagicMock()
        request.headers.get.return_value = None
        request.client.host = "192.0.2.1"

        result = request_metadata.extract_remote_address(request)

        assert result == "192.0.2.1"

    def test_extract_remote_address_with_multiple_ips(self):
        """Verify first IP is extracted from X-Forwarded-For with multiple IPs."""
        request = MagicMock()
        request.headers.get.side_effect = lambda key: {
            "x-forwarded-for": "203.0.113.1, 198.51.100.1, 192.0.2.1",
        }.get(key)

        result = request_metadata.extract_remote_address(request)

        assert result == "203.0.113.1"

    def test_extract_remote_address_returns_none_when_unavailable(self):
        """Verify None returned when no IP source available."""
        request = MagicMock()
        request.headers.get.return_value = None
        request.client = None

        result = request_metadata.extract_remote_address(request)

        assert result is None


class TestParseDeviceFromUserAgent:
    """Tests for parse_device_from_user_agent function."""

    def test_parse_device_from_user_agent_mobile(self):
        """Verify mobile device detection."""
        ua_string = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"

        result = request_metadata.parse_device_from_user_agent(ua_string)

        assert result is not None
        assert "Mobile" in result or "iPhone" in result

    def test_parse_device_from_user_agent_tablet(self):
        """Verify tablet device detection."""
        ua_string = "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"

        result = request_metadata.parse_device_from_user_agent(ua_string)

        assert result is not None
        assert "Tablet" in result or "iPad" in result

    def test_parse_device_from_user_agent_desktop(self):
        """Verify desktop/PC detection."""
        ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

        result = request_metadata.parse_device_from_user_agent(ua_string)

        assert result is not None
        assert "Desktop" in result or "Chrome" in result

    def test_parse_device_from_user_agent_bot(self):
        """Verify bot detection."""
        ua_string = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

        result = request_metadata.parse_device_from_user_agent(ua_string)

        assert result is not None
        assert "Bot" in result or "Googlebot" in result or "bot" in result.lower()

    def test_parse_device_from_user_agent_returns_none_for_invalid(self):
        """Verify None returned for None/empty user agent."""
        assert request_metadata.parse_device_from_user_agent(None) is None
        assert request_metadata.parse_device_from_user_agent("") is None

    def test_parse_device_from_user_agent_handles_exceptions(self):
        """Verify safe fallback for malformed user agent strings."""
        # This should not raise an exception
        result = request_metadata.parse_device_from_user_agent("invalid@@ua##string!!!")

        # Should return a safe default
        assert result is not None
        assert isinstance(result, str)


class TestHashSessionId:
    """Tests for hash_session_id function."""

    def test_hash_session_id(self):
        """Verify SHA-256 hash is computed correctly."""
        session_id = "test-session-12345"

        result = request_metadata.hash_session_id(session_id)

        # Verify it's a valid SHA-256 hash (64 hex characters)
        assert result is not None
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

        # Verify it matches expected hash
        expected = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        assert result == expected

    def test_hash_session_id_deterministic(self):
        """Verify same input produces same hash."""
        session_id = "test-session-67890"

        result1 = request_metadata.hash_session_id(session_id)
        result2 = request_metadata.hash_session_id(session_id)

        assert result1 == result2

    def test_hash_session_id_returns_none_for_none(self):
        """Verify None returned when session ID is None."""
        assert request_metadata.hash_session_id(None) is None

    def test_hash_session_id_returns_none_for_empty(self):
        """Verify None returned when session ID is empty string."""
        assert request_metadata.hash_session_id("") is None


class TestExtractRequestMetadata:
    """Tests for extract_request_metadata function."""

    def test_extract_request_metadata_full_integration(self):
        """Verify full metadata extraction with all fields present."""
        request = MagicMock()
        request.headers.get.side_effect = lambda key: {
            "x-forwarded-for": "203.0.113.1",
            "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        }.get(key)
        request.cookies.get.return_value = "test-session-abc123"
        request.client.host = "192.0.2.1"

        result = request_metadata.extract_request_metadata(request)

        # Verify all 4 required fields present
        assert "device" in result
        assert "remote_address" in result
        assert "session_id_hash" in result
        assert "user_agent" in result

        # Verify values
        assert result["remote_address"] == "203.0.113.1"
        assert result["user_agent"] == "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"
        assert result["device"] is not None
        assert result["session_id_hash"] is not None
        assert len(result["session_id_hash"]) == 64  # SHA-256 hash

    def test_extract_request_metadata_with_missing_fields(self):
        """Verify metadata extraction with missing optional fields."""
        request = MagicMock()
        request.headers.get.return_value = None
        request.cookies.get.return_value = None
        request.client = None

        result = request_metadata.extract_request_metadata(request)

        # Verify all 4 required fields present (but with None values)
        assert "device" in result
        assert "remote_address" in result
        assert "session_id_hash" in result
        assert "user_agent" in result

        # Verify all None
        assert result["device"] is None
        assert result["remote_address"] is None
        assert result["session_id_hash"] is None
        assert result["user_agent"] is None


class TestComputeMetadataHash:
    """Tests for compute_metadata_hash function."""

    def test_compute_metadata_hash_with_custom_fields(self):
        """Verify hash computation with custom metadata fields."""
        metadata = {
            "device": None,
            "user_agent": None,
            "remote_address": None,
            "session_id_hash": None,
            "custom_field": "test_value",
            "another_field": 123,
        }

        result = request_metadata.compute_metadata_hash(metadata)

        # Verify it's a valid MD5 hash (32 hex characters)
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_compute_metadata_hash_deterministic(self):
        """Verify same metadata produces same hash."""
        metadata = {
            "device": "Mobile iPhone",
            "user_agent": "Mozilla/5.0",
            "remote_address": "203.0.113.1",
            "session_id_hash": "abc123def456",
            "role": "admin",
            "email": "test@example.com",
        }

        result1 = request_metadata.compute_metadata_hash(metadata)
        result2 = request_metadata.compute_metadata_hash(metadata)

        assert result1 == result2

    def test_compute_metadata_hash_custom_field_order_matters(self):
        """Verify custom fields are sorted alphabetically."""
        # Same base fields, different custom field order
        metadata1 = {
            "device": None,
            "user_agent": None,
            "remote_address": None,
            "session_id_hash": None,
            "zebra": "value",
            "alpha": "value",
        }

        metadata2 = {
            "device": None,
            "user_agent": None,
            "remote_address": None,
            "session_id_hash": None,
            "alpha": "value",
            "zebra": "value",
        }

        result1 = request_metadata.compute_metadata_hash(metadata1)
        result2 = request_metadata.compute_metadata_hash(metadata2)

        # Should produce same hash (custom fields sorted alphabetically)
        assert result1 == result2

    def test_compute_metadata_hash_with_nested_structures(self):
        """Verify hash computation with nested dicts and arrays."""
        metadata = {
            "device": None,
            "user_agent": None,
            "remote_address": None,
            "session_id_hash": None,
            "nested_dict": {"key1": "value1", "key2": [1, 2, 3]},
            "array_field": ["a", "b", "c"],
        }

        result = request_metadata.compute_metadata_hash(metadata)

        # Verify hash is computed without errors
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_compute_metadata_hash_matches_postgresql_format(self):
        """Verify hash matches PostgreSQL's jsonb::text format.

        This is a regression test for the critical hash mismatch bug.
        PostgreSQL's jsonb::text produces keys in this order for base fields:
        device, user_agent, remote_address, session_id_hash
        """
        metadata = {
            "device": None,
            "user_agent": None,
            "remote_address": None,
            "session_id_hash": None,
        }

        result = request_metadata.compute_metadata_hash(metadata)

        # Expected JSON string format matching PostgreSQL:
        # {"device": null, "user_agent": null, "remote_address": null, "session_id_hash": null}
        expected_json = '{"device": null, "user_agent": null, "remote_address": null, "session_id_hash": null}'
        expected_hash = hashlib.md5(expected_json.encode("utf-8")).hexdigest()

        assert result == expected_hash
