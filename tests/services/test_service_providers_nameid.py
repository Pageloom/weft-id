"""Tests for NameID resolution logic."""

from unittest.mock import patch

from constants.nameid_formats import (
    NAMEID_FORMAT_EMAIL,
    NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_TRANSIENT,
    NAMEID_FORMAT_UNSPECIFIED,
)
from services.service_providers.nameid import resolve_name_id


class TestResolveNameIdEmail:
    """emailAddress format returns the user's email."""

    @patch("services.service_providers.nameid.database")
    def test_email_format_returns_email(self, mock_db):
        value, fmt = resolve_name_id(
            tenant_id="t1",
            user_id="u1",
            sp_id="sp1",
            nameid_format=NAMEID_FORMAT_EMAIL,
            user_email="alice@example.com",
        )

        assert value == "alice@example.com"
        assert fmt == NAMEID_FORMAT_EMAIL


class TestResolveNameIdUnspecified:
    """unspecified format returns the user's email with unspecified URI."""

    @patch("services.service_providers.nameid.database")
    def test_unspecified_format_returns_email(self, mock_db):
        value, fmt = resolve_name_id(
            tenant_id="t1",
            user_id="u1",
            sp_id="sp1",
            nameid_format=NAMEID_FORMAT_UNSPECIFIED,
            user_email="bob@example.com",
        )

        assert value == "bob@example.com"
        assert fmt == NAMEID_FORMAT_UNSPECIFIED


class TestResolveNameIdPersistent:
    """persistent format creates a mapping on first SSO and reuses on subsequent."""

    @patch("services.service_providers.nameid.database")
    def test_persistent_creates_mapping(self, mock_db):
        mock_db.sp_nameid_mappings.get_or_create_nameid_mapping.return_value = {
            "nameid_value": "opaque-id-123",
        }

        value, fmt = resolve_name_id(
            tenant_id="t1",
            user_id="u1",
            sp_id="sp1",
            nameid_format=NAMEID_FORMAT_PERSISTENT,
            user_email="alice@example.com",
        )

        assert value == "opaque-id-123"
        assert fmt == NAMEID_FORMAT_PERSISTENT
        mock_db.sp_nameid_mappings.get_or_create_nameid_mapping.assert_called_once_with(
            tenant_id="t1",
            tenant_id_value="t1",
            user_id="u1",
            sp_id="sp1",
        )

    @patch("services.service_providers.nameid.database")
    def test_persistent_reuses_existing_mapping(self, mock_db):
        """Calling twice with the same user/SP returns the same value."""
        mock_db.sp_nameid_mappings.get_or_create_nameid_mapping.return_value = {
            "nameid_value": "stable-id-456",
        }

        v1, _ = resolve_name_id("t1", "u1", "sp1", NAMEID_FORMAT_PERSISTENT, "a@b.com")
        v2, _ = resolve_name_id("t1", "u1", "sp1", NAMEID_FORMAT_PERSISTENT, "a@b.com")

        assert v1 == v2 == "stable-id-456"

    @patch("services.service_providers.nameid.database")
    def test_persistent_different_sps_get_different_values(self, mock_db):
        """Different SPs get different persistent IDs for the same user."""
        mock_db.sp_nameid_mappings.get_or_create_nameid_mapping.side_effect = [
            {"nameid_value": "id-for-sp1"},
            {"nameid_value": "id-for-sp2"},
        ]

        v1, _ = resolve_name_id("t1", "u1", "sp1", NAMEID_FORMAT_PERSISTENT, "a@b.com")
        v2, _ = resolve_name_id("t1", "u1", "sp2", NAMEID_FORMAT_PERSISTENT, "a@b.com")

        assert v1 != v2


class TestResolveNameIdTransient:
    """transient format returns a UUID, different each call."""

    @patch("services.service_providers.nameid.database")
    def test_transient_returns_uuid(self, mock_db):
        import uuid

        value, fmt = resolve_name_id(
            tenant_id="t1",
            user_id="u1",
            sp_id="sp1",
            nameid_format=NAMEID_FORMAT_TRANSIENT,
            user_email="alice@example.com",
        )

        # Should be a valid UUID
        uuid.UUID(value)
        assert fmt == NAMEID_FORMAT_TRANSIENT

    @patch("services.service_providers.nameid.database")
    def test_transient_different_each_call(self, mock_db):
        v1, _ = resolve_name_id("t1", "u1", "sp1", NAMEID_FORMAT_TRANSIENT, "a@b.com")
        v2, _ = resolve_name_id("t1", "u1", "sp1", NAMEID_FORMAT_TRANSIENT, "a@b.com")

        assert v1 != v2


class TestResolveNameIdUnknown:
    """Unknown format falls back to email."""

    @patch("services.service_providers.nameid.database")
    def test_unknown_format_falls_back_to_email(self, mock_db):
        value, fmt = resolve_name_id(
            tenant_id="t1",
            user_id="u1",
            sp_id="sp1",
            nameid_format="urn:some:unknown:format",
            user_email="alice@example.com",
        )

        assert value == "alice@example.com"
        assert fmt == NAMEID_FORMAT_EMAIL
