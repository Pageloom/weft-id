"""Unit tests for resend_invitation service function."""

from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError

# =============================================================================
# Success Cases
# =============================================================================


def test_resend_invitation_verified_email(make_requesting_user, make_user_dict):
    """Test resend invitation for user with verified primary email (set-password flow)."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    email_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=False)

    new_nonce = "abc123randomtoken"

    primary_email = {
        "id": email_id,
        "email": "user@example.com",
        "verified_at": "2026-01-01T00:00:00Z",
        "verify_nonce": "oldverifynonce",
        "set_password_nonce": "oldspnonce",
    }

    with (
        patch("services.users.crud.database") as mock_db,
        patch("services.users.crud.log_event") as mock_log,
    ):
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.user_emails.get_primary_email_for_resend.return_value = primary_email
        mock_db.user_emails.regenerate_set_password_nonce.return_value = new_nonce

        result = users_service.resend_invitation(requesting_user, target_id)

    assert result["email_id"] == email_id
    assert result["email"] == "user@example.com"
    assert result["nonce"] == new_nonce
    assert result["invitation_type"] == "set_password"

    mock_db.user_emails.regenerate_set_password_nonce.assert_called_once_with(tenant_id, email_id)
    mock_log.assert_called_once()
    log_kwargs = mock_log.call_args[1]
    assert log_kwargs["event_type"] == "invitation_resent"
    assert log_kwargs["artifact_id"] == target_id
    assert log_kwargs["metadata"]["invitation_type"] == "set_password"


def test_resend_invitation_unverified_email(make_requesting_user, make_user_dict):
    """Test resend invitation for user with unverified email (verification flow)."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    email_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=False)

    new_nonce = "xyz789randomtoken"

    primary_email = {
        "id": email_id,
        "email": "user@example.com",
        "verified_at": None,
        "verify_nonce": "oldverifynonce",
        "set_password_nonce": "oldspnonce",
    }

    with (
        patch("services.users.crud.database") as mock_db,
        patch("services.users.crud.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.user_emails.get_primary_email_for_resend.return_value = primary_email
        mock_db.user_emails.regenerate_verify_nonce.return_value = new_nonce

        result = users_service.resend_invitation(requesting_user, target_id)

    assert result["email_id"] == email_id
    assert result["email"] == "user@example.com"
    assert result["nonce"] == new_nonce
    assert result["invitation_type"] == "verify"

    mock_db.user_emails.regenerate_verify_nonce.assert_called_once_with(tenant_id, email_id)


def test_resend_invitation_as_super_admin(make_requesting_user, make_user_dict):
    """Test super_admin can also resend invitations."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

    target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=False)

    primary_email = {
        "id": str(uuid4()),
        "email": "user@example.com",
        "verified_at": "2026-01-01T00:00:00Z",
        "verify_nonce": "somenonce",
        "set_password_nonce": "somenonce",
    }

    with (
        patch("services.users.crud.database") as mock_db,
        patch("services.users.crud.log_event"),
    ):
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.user_emails.get_primary_email_for_resend.return_value = primary_email
        mock_db.user_emails.regenerate_set_password_nonce.return_value = "newnonce"

        result = users_service.resend_invitation(requesting_user, target_id)

    assert result["invitation_type"] == "set_password"


# =============================================================================
# Authorization Failures
# =============================================================================


def test_resend_invitation_member_denied(make_requesting_user):
    """Test member role cannot resend invitations."""
    from services import users as users_service

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        users_service.resend_invitation(requesting_user, str(uuid4()))


# =============================================================================
# Validation Failures
# =============================================================================


def test_resend_invitation_user_not_found(make_requesting_user):
    """Test resend fails when target user doesn't exist."""
    from services import users as users_service

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with patch("services.users.crud.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = None

        with pytest.raises(NotFoundError, match="User not found"):
            users_service.resend_invitation(requesting_user, str(uuid4()))


def test_resend_invitation_already_onboarded(make_requesting_user, make_user_dict):
    """Test resend fails when user has already set a password."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=True)

    with patch("services.users.crud.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = target_user

        with pytest.raises(ValidationError) as exc_info:
            users_service.resend_invitation(requesting_user, target_id)
        assert exc_info.value.code == "already_onboarded"


def test_resend_invitation_inactivated_user(make_requesting_user, make_user_dict):
    """Test resend fails for inactivated users."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    target_user = make_user_dict(
        user_id=target_id,
        tenant_id=tenant_id,
        has_password=False,
        is_inactivated=True,
    )

    with patch("services.users.crud.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = target_user

        with pytest.raises(ValidationError) as exc_info:
            users_service.resend_invitation(requesting_user, target_id)
        assert exc_info.value.code == "user_inactivated"


def test_resend_invitation_anonymized_user(make_requesting_user, make_user_dict):
    """Test resend fails for anonymized users."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    target_user = make_user_dict(
        user_id=target_id,
        tenant_id=tenant_id,
        has_password=False,
        is_anonymized=True,
    )

    with patch("services.users.crud.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = target_user

        with pytest.raises(ValidationError) as exc_info:
            users_service.resend_invitation(requesting_user, target_id)
        assert exc_info.value.code == "user_anonymized"


def test_resend_invitation_no_primary_email(make_requesting_user, make_user_dict):
    """Test resend fails when user has no primary email."""
    from services import users as users_service

    tenant_id = str(uuid4())
    target_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    target_user = make_user_dict(user_id=target_id, tenant_id=tenant_id, has_password=False)

    with patch("services.users.crud.database") as mock_db:
        mock_db.users.get_user_by_id.return_value = target_user
        mock_db.user_emails.get_primary_email_for_resend.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            users_service.resend_invitation(requesting_user, target_id)
        assert exc_info.value.code == "no_primary_email"
