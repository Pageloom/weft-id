"""Unit tests for password change and force reset service functions."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from services.exceptions import NotFoundError, ValidationError


class TestChangePassword:
    """Tests for users.change_password()."""

    def test_change_password_success(self, make_requesting_user):
        from services.users.password import change_password

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

        strength_result = MagicMock()
        strength_result.is_valid = True

        with (
            patch("services.users.password.database") as mock_db,
            patch("services.users.password.verify_password", return_value=True),
            patch("services.users.password.validate_password", return_value=strength_result),
            patch("services.users.password.hash_password", return_value="new_hash"),
            patch("services.users.password.log_event") as mock_log,
        ):
            mock_db.users.get_password_hash.return_value = "$argon2id$hash"
            mock_db.security.get_password_policy.return_value = {
                "minimum_password_length": 14,
                "minimum_zxcvbn_score": 3,
            }
            mock_db.user_emails.get_primary_email.return_value = {"email": "test@example.com"}

            change_password(requesting_user, "old_password", "new_strong_password")

            mock_db.users.update_password.assert_called_once_with(tenant_id, user_id, "new_hash")
            mock_log.assert_called_once()
            assert mock_log.call_args.kwargs["event_type"] == "password_changed"

    def test_change_password_wrong_current(self, make_requesting_user):
        from services.users.password import change_password

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

        with (
            patch("services.users.password.database") as mock_db,
            patch("services.users.password.verify_password", return_value=False),
        ):
            mock_db.users.get_password_hash.return_value = "$argon2id$hash"

            with pytest.raises(ValidationError) as exc_info:
                change_password(requesting_user, "wrong_password", "new_password")
            assert exc_info.value.code == "invalid_current_password"

    def test_change_password_no_password_user(self, make_requesting_user):
        from services.users.password import change_password

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

        with patch("services.users.password.database") as mock_db:
            mock_db.users.get_password_hash.return_value = None

            with pytest.raises(ValidationError) as exc_info:
                change_password(requesting_user, "old", "new")
            assert exc_info.value.code == "no_password"

    def test_change_password_weak_new_password(self, make_requesting_user):
        from services.users.password import change_password

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="member")

        strength_result = MagicMock()
        strength_result.is_valid = False
        strength_result.issues = [MagicMock(message="Password too weak")]

        with (
            patch("services.users.password.database") as mock_db,
            patch("services.users.password.verify_password", return_value=True),
            patch("services.users.password.validate_password", return_value=strength_result),
        ):
            mock_db.users.get_password_hash.return_value = "$argon2id$hash"
            mock_db.security.get_password_policy.return_value = {
                "minimum_password_length": 14,
                "minimum_zxcvbn_score": 3,
            }
            mock_db.user_emails.get_primary_email.return_value = {"email": "test@example.com"}

            with pytest.raises(ValidationError) as exc_info:
                change_password(requesting_user, "old_password", "weak")
            assert exc_info.value.code == "password_too_weak"


class TestForcePasswordReset:
    """Tests for users.force_password_reset()."""

    def test_force_reset_success(self, make_requesting_user, make_user_dict):
        from services.users.password import force_password_reset

        tenant_id = str(uuid4())
        admin_id = str(uuid4())
        target_id = str(uuid4())
        requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

        target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=True)

        with (
            patch("services.users.password.database") as mock_db,
            patch("services.users.password.log_event") as mock_log,
        ):
            mock_db.users.get_user_by_id.return_value = target_user

            force_password_reset(requesting_user, target_id)

            mock_db.users.set_password_reset_required.assert_called_once_with(
                tenant_id, target_id, True
            )
            mock_log.assert_called_once()
            assert mock_log.call_args.kwargs["event_type"] == "password_reset_forced"
            assert mock_log.call_args.kwargs["artifact_id"] == target_id

    def test_force_reset_self_rejected(self, make_requesting_user):
        from services.users.password import force_password_reset

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        requesting_user = make_requesting_user(user_id=user_id, tenant_id=tenant_id, role="admin")

        with pytest.raises(ValidationError) as exc_info:
            force_password_reset(requesting_user, user_id)
        assert exc_info.value.code == "cannot_force_reset_self"

    def test_force_reset_member_forbidden(self, make_requesting_user):
        from services.exceptions import ForbiddenError
        from services.users.password import force_password_reset

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="member")

        with pytest.raises(ForbiddenError):
            force_password_reset(requesting_user, str(uuid4()))

    def test_force_reset_user_not_found(self, make_requesting_user):
        from services.users.password import force_password_reset

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with patch("services.users.password.database") as mock_db:
            mock_db.users.get_user_by_id.return_value = None

            with pytest.raises(NotFoundError):
                force_password_reset(requesting_user, str(uuid4()))

    def test_force_reset_idp_user_rejected(self, make_requesting_user, make_user_dict):
        from services.users.password import force_password_reset

        tenant_id = str(uuid4())
        target_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=False)

        with patch("services.users.password.database") as mock_db:
            mock_db.users.get_user_by_id.return_value = target_user

            with pytest.raises(ValidationError) as exc_info:
                force_password_reset(requesting_user, target_id)
            assert exc_info.value.code == "no_password"

    def test_force_reset_inactivated_user_rejected(self, make_requesting_user, make_user_dict):
        from services.users.password import force_password_reset

        tenant_id = str(uuid4())
        target_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        target_user = make_user_dict(
            user_id=target_id,
            tenant_id=tenant_id,
            has_password=True,
            is_inactivated=True,
        )

        with patch("services.users.password.database") as mock_db:
            mock_db.users.get_user_by_id.return_value = target_user

            with pytest.raises(ValidationError) as exc_info:
                force_password_reset(requesting_user, target_id)
            assert exc_info.value.code == "user_inactivated"


class TestCompleteForcedPasswordReset:
    """Tests for users.complete_forced_password_reset()."""

    def test_complete_reset_success(self, make_user_dict):
        from services.users.password import complete_forced_password_reset

        tenant_id = str(uuid4())
        user_id = str(uuid4())

        user = make_user_dict(user_id=user_id, tenant_id=tenant_id)

        strength_result = MagicMock()
        strength_result.is_valid = True

        with (
            patch("services.users.password.database") as mock_db,
            patch("services.users.password.validate_password", return_value=strength_result),
            patch("services.users.password.hash_password", return_value="new_hash"),
            patch("services.users.password.log_event") as mock_log,
        ):
            mock_db.users.get_user_by_id.return_value = user
            mock_db.security.get_password_policy.return_value = {
                "minimum_password_length": 14,
                "minimum_zxcvbn_score": 3,
            }
            mock_db.user_emails.get_primary_email.return_value = {"email": "test@example.com"}

            complete_forced_password_reset(tenant_id, user_id, "new_strong_password")

            mock_db.users.update_password.assert_called_once_with(tenant_id, user_id, "new_hash")
            mock_log.assert_called_once()
            assert mock_log.call_args.kwargs["event_type"] == "password_reset_completed"

    def test_complete_reset_weak_password(self, make_user_dict):
        from services.users.password import complete_forced_password_reset

        tenant_id = str(uuid4())
        user_id = str(uuid4())

        user = make_user_dict(user_id=user_id, tenant_id=tenant_id)

        strength_result = MagicMock()
        strength_result.is_valid = False
        strength_result.issues = [MagicMock(message="Too weak")]

        with (
            patch("services.users.password.database") as mock_db,
            patch("services.users.password.validate_password", return_value=strength_result),
        ):
            mock_db.users.get_user_by_id.return_value = user
            mock_db.security.get_password_policy.return_value = {
                "minimum_password_length": 14,
                "minimum_zxcvbn_score": 3,
            }
            mock_db.user_emails.get_primary_email.return_value = {"email": "test@example.com"}

            with pytest.raises(ValidationError) as exc_info:
                complete_forced_password_reset(tenant_id, user_id, "weak")
            assert exc_info.value.code == "password_too_weak"
