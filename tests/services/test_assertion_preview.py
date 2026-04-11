"""Tests for downstream SP assertion preview feature."""

from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.service_providers.sso import preview_assertion
from services.types import RequestingUser


def _make_requesting_user(role: str = "super_admin") -> RequestingUser:
    return RequestingUser(
        id=str(uuid4()),
        tenant_id=str(uuid4()),
        role=role,
    )


def _make_sp_row(**overrides) -> dict:
    defaults = {
        "id": uuid4(),
        "name": "Test SP",
        "entity_id": "https://sp.example.com",
        "acs_url": "https://sp.example.com/acs",
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "include_group_claims": True,
        "group_assertion_scope": "access_relevant",
        "attribute_mapping": None,
        "encryption_certificate_pem": None,
        "assertion_encryption_algorithm": "aes256-cbc",
        "available_to_all": False,
        "trust_established": True,
    }
    defaults.update(overrides)
    return defaults


def _make_user_row(**overrides) -> dict:
    defaults = {
        "id": uuid4(),
        "first_name": "Alice",
        "last_name": "Smith",
        "role": "member",
    }
    defaults.update(overrides)
    return defaults


# =============================================================================
# Authorization
# =============================================================================


class TestPreviewAssertionAuth:
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_requires_super_admin(self, mock_db, mock_track, mock_log):
        requesting_user = _make_requesting_user(role="admin")

        with pytest.raises(ForbiddenError) as exc_info:
            preview_assertion(requesting_user, str(uuid4()), str(uuid4()))

        assert exc_info.value.code == "super_admin_required"

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_member_forbidden(self, mock_db, mock_track, mock_log):
        requesting_user = _make_requesting_user(role="member")

        with pytest.raises(ForbiddenError):
            preview_assertion(requesting_user, str(uuid4()), str(uuid4()))


# =============================================================================
# Not Found Cases
# =============================================================================


class TestPreviewAssertionNotFound:
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_sp_not_found(self, mock_db, mock_track, mock_log):
        mock_db.service_providers.get_service_provider.return_value = None
        requesting_user = _make_requesting_user()

        with pytest.raises(NotFoundError) as exc_info:
            preview_assertion(requesting_user, str(uuid4()), str(uuid4()))

        assert exc_info.value.code == "sp_not_found"

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_user_not_found(self, mock_db, mock_track, mock_log):
        mock_db.service_providers.get_service_provider.return_value = _make_sp_row()
        mock_db.users.get_user_by_id.return_value = None
        requesting_user = _make_requesting_user()

        with pytest.raises(NotFoundError) as exc_info:
            preview_assertion(requesting_user, str(uuid4()), str(uuid4()))

        assert exc_info.value.code == "user_not_found"

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_user_no_primary_email(self, mock_db, mock_track, mock_log):
        mock_db.service_providers.get_service_provider.return_value = _make_sp_row()
        mock_db.users.get_user_by_id.return_value = _make_user_row()
        mock_db.user_emails.get_primary_email.return_value = None
        requesting_user = _make_requesting_user()

        with pytest.raises(ValidationError) as exc_info:
            preview_assertion(requesting_user, str(uuid4()), str(uuid4()))

        assert exc_info.value.code == "user_no_email"


# =============================================================================
# Happy Path
# =============================================================================


class TestPreviewAssertionHappyPath:
    @patch("services.service_providers.group_assignments.check_user_sp_access", return_value=True)
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_basic_preview(self, mock_db, mock_track, mock_log, mock_access):
        sp_row = _make_sp_row()
        user_row = _make_user_row()
        sp_id = str(sp_row["id"])
        user_id = str(user_row["id"])

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "alice@example.com"}
        mock_db.groups.get_access_relevant_group_names.return_value = ["Engineering"]
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        result = preview_assertion(requesting_user, sp_id, user_id)

        assert result.user_email == "alice@example.com"
        assert result.user_first_name == "Alice"
        assert result.user_last_name == "Smith"
        assert result.sp_name == "Test SP"
        assert result.has_access is True
        assert result.assertion_encrypted is False
        assert "Engineering" in result.group_names
        assert result.attributes["email"] == "alice@example.com"
        assert result.attributes["firstName"] == "Alice"
        assert result.attributes["lastName"] == "Smith"
        assert result.attributes["displayName"] == "Alice Smith"

    @patch("services.service_providers.group_assignments.check_user_sp_access", return_value=False)
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_no_access(self, mock_db, mock_track, mock_log, mock_access):
        sp_row = _make_sp_row(available_to_all=False)
        user_row = _make_user_row()

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "bob@example.com"}
        mock_db.groups.get_access_relevant_group_names.return_value = []
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        result = preview_assertion(requesting_user, str(sp_row["id"]), str(user_row["id"]))

        assert result.has_access is False
        assert result.group_names == []

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_available_to_all(self, mock_db, mock_track, mock_log):
        sp_row = _make_sp_row(available_to_all=True)
        user_row = _make_user_row()

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "carol@example.com"}
        mock_db.groups.get_trunk_group_names.return_value = ["All Users"]
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        result = preview_assertion(requesting_user, str(sp_row["id"]), str(user_row["id"]))

        assert result.has_access is True

    @patch("services.service_providers.group_assignments.check_user_sp_access", return_value=True)
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_encrypted_assertion(self, mock_db, mock_track, mock_log, mock_access):
        enc_cert = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
        sp_row = _make_sp_row(
            encryption_certificate_pem=enc_cert,
            assertion_encryption_algorithm="aes256-gcm",
        )
        user_row = _make_user_row()

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "dave@example.com"}
        mock_db.groups.get_access_relevant_group_names.return_value = []
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        result = preview_assertion(requesting_user, str(sp_row["id"]), str(user_row["id"]))

        assert result.assertion_encrypted is True
        assert result.encryption_algorithm == "aes256-gcm"

    @patch("services.service_providers.group_assignments.check_user_sp_access", return_value=True)
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_logs_event(self, mock_db, mock_track, mock_log, mock_access):
        sp_row = _make_sp_row()
        user_row = _make_user_row()

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "eve@example.com"}
        mock_db.groups.get_access_relevant_group_names.return_value = []
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        preview_assertion(requesting_user, str(sp_row["id"]), str(user_row["id"]))

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["event_type"] == "assertion_preview_viewed"
        assert call_kwargs["artifact_type"] == "service_provider"

    @patch("services.service_providers.group_assignments.check_user_sp_access", return_value=True)
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_with_attribute_mapping(self, mock_db, mock_track, mock_log, mock_access):
        sp_row = _make_sp_row(
            attribute_mapping={"email": "http://claims/email", "groups": "memberOf"}
        )
        user_row = _make_user_row()

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "frank@example.com"}
        mock_db.groups.get_access_relevant_group_names.return_value = []
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        result = preview_assertion(requesting_user, str(sp_row["id"]), str(user_row["id"]))

        assert result.attribute_mapping == {
            "email": "http://claims/email",
            "groups": "memberOf",
        }

    @patch("services.service_providers.group_assignments.check_user_sp_access", return_value=True)
    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.track_activity")
    @patch("services.service_providers.sso.database")
    def test_no_group_claims(self, mock_db, mock_track, mock_log, mock_access):
        sp_row = _make_sp_row(include_group_claims=False)
        user_row = _make_user_row()

        mock_db.service_providers.get_service_provider.return_value = sp_row
        mock_db.users.get_user_by_id.return_value = user_row
        mock_db.user_emails.get_primary_email.return_value = {"email": "grace@example.com"}
        mock_db.security.get_group_assertion_scope.return_value = "access_relevant"

        requesting_user = _make_requesting_user()
        result = preview_assertion(requesting_user, str(sp_row["id"]), str(user_row["id"]))

        assert result.group_names == []
        assert "groups" not in result.attributes
