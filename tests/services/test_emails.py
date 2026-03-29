"""Comprehensive tests for email service layer functions.

This test file covers all email service operations for the services/emails.py module.
Tests focus on:
- Authorization (admin vs user access)
- Email CRUD operations
- Email verification flow
- Event logging
- Error cases
"""

import database
import pytest
from services import emails as emails_service
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError
from services.types import RequestingUser

# =============================================================================
# Test Helpers
# =============================================================================


def _make_requesting_user(user: dict, tenant_id: str, role: str | None = None) -> RequestingUser:
    """Create a RequestingUser for testing."""
    return {
        "id": str(user["id"]),
        "tenant_id": tenant_id,
        "role": role or user["role"],
    }


def _verify_event_logged(tenant_id: str, event_type: str, artifact_id: str):
    """Verify an event was logged."""
    events = database.event_log.list_events(tenant_id, limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == event_type
    assert str(events[0]["artifact_id"]) == str(artifact_id)


def _add_unverified_email(tenant_id: str, user_id: str, email: str) -> dict:
    """Helper to add an unverified email."""
    result = database.user_emails.add_email(
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        tenant_id_value=tenant_id,
    )
    return result


# =============================================================================
# List User Emails Tests
# =============================================================================


def test_list_user_emails_as_admin(test_tenant, test_admin_user, test_user):
    """Test that admin can list any user's emails."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    result = emails_service.list_user_emails(requesting_user, str(test_user["id"]))

    assert len(result) >= 1
    assert any(e.email == test_user["email"] for e in result)


def test_list_user_emails_as_self(test_tenant, test_user):
    """Test that user can list their own emails."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    result = emails_service.list_user_emails(requesting_user, str(test_user["id"]))

    assert len(result) >= 1
    assert any(e.email == test_user["email"] for e in result)


def test_list_user_emails_as_member_forbidden(test_tenant, test_user, test_admin_user):
    """Test that member cannot list other user's emails."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        emails_service.list_user_emails(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "email_access_denied"


def test_list_user_emails_user_not_found(test_tenant, test_admin_user):
    """Test listing emails for non-existent user returns NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        emails_service.list_user_emails(requesting_user, "00000000-0000-0000-0000-000000000000")

    assert exc_info.value.code == "user_not_found"


# =============================================================================
# Add User Email Tests
# =============================================================================


def test_add_user_email_as_admin_auto_verified(test_tenant, test_admin_user, test_user):
    """Test that admin adding email auto-verifies it."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    new_email = f"admin-added-{str(test_user['id'])[:8]}@example.com"

    result = emails_service.add_user_email(
        requesting_user,
        str(test_user["id"]),
        new_email,
        is_admin_action=True,
    )

    assert result.email == new_email.lower()
    assert result.verified_at is not None  # Auto-verified
    assert result.is_primary is False

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "email_added"
    assert events[0]["metadata"]["is_admin_action"] is True
    assert events[0]["metadata"]["auto_verified"] is True


def test_add_user_email_as_user_requires_verification(test_tenant, test_user):
    """Test that user adding email requires verification."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    new_email = f"user-added-{str(test_user['id'])[:8]}@example.com"

    result = emails_service.add_user_email(
        requesting_user,
        str(test_user["id"]),
        new_email,
        is_admin_action=False,
    )

    assert result.email == new_email.lower()
    assert result.verified_at is None  # Not verified
    assert result.is_primary is False

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "email_added"
    assert events[0]["metadata"]["is_admin_action"] is False


def test_add_user_email_normalizes_email(test_tenant, test_user):
    """Test that email addresses are normalized to lowercase."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    new_email = f"UPPERCASE-{str(test_user['id'])[:8]}@EXAMPLE.COM"

    result = emails_service.add_user_email(
        requesting_user,
        str(test_user["id"]),
        new_email,
        is_admin_action=False,
    )

    assert result.email == new_email.lower()


def test_add_user_email_forbidden_for_other_user(test_tenant, test_user, test_admin_user):
    """Test that member cannot add email to other user's account."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        emails_service.add_user_email(
            requesting_user,
            test_admin_user["id"],
            "unauthorized@example.com",
            is_admin_action=False,
        )

    assert exc_info.value.code == "email_access_denied"


def test_add_user_email_conflict(test_tenant, test_user):
    """Test adding duplicate email returns ConflictError."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ConflictError) as exc_info:
        emails_service.add_user_email(
            requesting_user,
            str(test_user["id"]),
            test_user["email"],  # Existing email
            is_admin_action=False,
        )

    assert exc_info.value.code == "email_exists"


def test_add_user_email_user_not_found(test_tenant, test_admin_user):
    """Test adding email to non-existent user returns NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        emails_service.add_user_email(
            requesting_user,
            "00000000-0000-0000-0000-000000000000",
            "test@example.com",
            is_admin_action=True,
        )

    assert exc_info.value.code == "user_not_found"


# =============================================================================
# Delete User Email Tests
# =============================================================================


def test_delete_user_email_as_admin(test_tenant, test_admin_user, test_user):
    """Test that admin can delete any user's email."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Add a secondary email to delete
    new_email = f"delete-me-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    # Delete it
    emails_service.delete_user_email(requesting_user, str(test_user["id"]), str(added["id"]))

    # Verify it's gone
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    assert not any(e["email"] == new_email for e in emails)

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "email_deleted"
    assert events[0]["metadata"]["email"] == new_email


def test_delete_user_email_as_self(test_tenant, test_user):
    """Test that user can delete their own email."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Add a secondary email
    new_email = f"self-delete-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    # Delete it
    emails_service.delete_user_email(requesting_user, str(test_user["id"]), str(added["id"]))

    # Verify it's gone
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    assert not any(e["email"] == new_email for e in emails)


def test_delete_user_email_forbidden_for_other_user(test_tenant, test_user, test_admin_user):
    """Test that member cannot delete other user's email."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Get admin's primary email
    admin_emails = database.user_emails.list_user_emails(test_tenant["id"], test_admin_user["id"])
    admin_email_id = str(admin_emails[0]["id"])

    with pytest.raises(ForbiddenError) as exc_info:
        emails_service.delete_user_email(
            requesting_user, str(test_admin_user["id"]), admin_email_id
        )

    assert exc_info.value.code == "email_access_denied"


def test_delete_user_email_not_found(test_tenant, test_admin_user, test_user):
    """Test deleting non-existent email returns NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        emails_service.delete_user_email(
            requesting_user,
            str(test_user["id"]),
            "00000000-0000-0000-0000-000000000000",
        )

    assert exc_info.value.code == "email_not_found"


def test_delete_primary_email_forbidden(test_tenant, test_user):
    """Test that primary email cannot be deleted."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Get primary email ID
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    primary_email = next(e for e in emails if e["is_primary"])

    with pytest.raises(ValidationError) as exc_info:
        emails_service.delete_user_email(
            requesting_user, str(test_user["id"]), str(primary_email["id"])
        )

    assert exc_info.value.code == "cannot_delete_primary"


def test_delete_last_email_forbidden(test_tenant, test_user):
    """Test that user must keep at least one email."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # User has only one email (primary)
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    assert len(emails) == 1

    with pytest.raises(ValidationError) as exc_info:
        emails_service.delete_user_email(
            requesting_user, str(test_user["id"]), str(emails[0]["id"])
        )

    assert exc_info.value.code in ("cannot_delete_primary", "must_keep_one_email")


# =============================================================================
# Set Primary Email Tests
# =============================================================================


def test_set_primary_email_as_admin(test_tenant, test_admin_user, test_user):
    """Test that admin can set primary email for any user."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Add and verify a secondary email
    new_email = f"new-primary-{str(test_user['id'])[:8]}@example.com"
    added = database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
        email=new_email,
        is_primary=False,
    )

    # Set as primary
    result = emails_service.set_primary_email(
        requesting_user, str(test_user["id"]), str(added["id"])
    )

    assert result.email == new_email
    assert result.is_primary is True

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "primary_email_changed"
    assert events[0]["metadata"]["email"] == new_email


def test_set_primary_email_as_self(test_tenant, test_user):
    """Test that user can set their own primary email."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Add and verify a secondary email
    new_email = f"self-primary-{str(test_user['id'])[:8]}@example.com"
    added = database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
        email=new_email,
        is_primary=False,
    )

    # Set as primary
    result = emails_service.set_primary_email(
        requesting_user, str(test_user["id"]), str(added["id"])
    )

    assert result.email == new_email
    assert result.is_primary is True


def test_set_primary_email_forbidden_for_other_user(test_tenant, test_user, test_admin_user):
    """Test that member cannot set primary email for other user."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Get admin's email
    admin_emails = database.user_emails.list_user_emails(test_tenant["id"], test_admin_user["id"])

    with pytest.raises(ForbiddenError) as exc_info:
        emails_service.set_primary_email(
            requesting_user,
            str(test_admin_user["id"]),
            str(admin_emails[0]["id"]),
        )

    assert exc_info.value.code == "email_access_denied"


def test_set_primary_email_not_found(test_tenant, test_admin_user, test_user):
    """Test setting non-existent email as primary returns NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        emails_service.set_primary_email(
            requesting_user,
            str(test_user["id"]),
            "00000000-0000-0000-0000-000000000000",
        )

    assert exc_info.value.code == "email_not_found"


def test_set_primary_email_unverified_forbidden(test_tenant, test_user):
    """Test that unverified email cannot be set as primary."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Add unverified email
    new_email = f"unverified-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    with pytest.raises(ValidationError) as exc_info:
        emails_service.set_primary_email(requesting_user, str(test_user["id"]), str(added["id"]))

    assert exc_info.value.code == "email_not_verified"


def test_set_primary_email_already_primary_idempotent(test_tenant, test_user):
    """Test setting already-primary email is idempotent."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Get primary email
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    primary_email = next(e for e in emails if e["is_primary"])

    result = emails_service.set_primary_email(
        requesting_user, str(test_user["id"]), str(primary_email["id"])
    )

    assert result.email == primary_email["email"]
    assert result.is_primary is True


# =============================================================================
# Email Verification Tests
# =============================================================================


def test_verify_email_success(test_tenant, test_user):
    """Test verifying an email with correct nonce."""
    # Add unverified email
    new_email = f"verify-success-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    # Verify it
    result = emails_service.verify_email(
        test_tenant["id"],
        str(added["id"]),
        str(test_user["id"]),
        added["verify_nonce"],
    )

    assert result.email == new_email
    assert result.verified_at is not None

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "email_verified"
    assert events[0]["metadata"]["email"] == new_email


def test_verify_email_not_found(test_tenant, test_user):
    """Test verifying non-existent email returns NotFoundError."""
    with pytest.raises(NotFoundError) as exc_info:
        emails_service.verify_email(
            test_tenant["id"],
            "00000000-0000-0000-0000-000000000000",
            test_user["id"],
            12345,
        )

    assert exc_info.value.code == "email_not_found"


def test_verify_email_wrong_user(test_tenant, test_user, test_admin_user):
    """Test verifying email with wrong user_id returns NotFoundError."""
    # Add unverified email to test_user
    new_email = f"verify-wrong-user-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    # Try to verify as admin_user
    with pytest.raises(NotFoundError) as exc_info:
        emails_service.verify_email(
            test_tenant["id"],
            str(added["id"]),
            str(test_admin_user["id"]),  # Wrong user
            added["verify_nonce"],
        )

    assert exc_info.value.code == "email_not_found"


def test_verify_email_already_verified(test_tenant, test_user):
    """Test verifying already-verified email returns ValidationError."""
    # User's primary email is already verified
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    primary_email = next(e for e in emails if e["is_primary"])

    # Get verification nonce (won't be used since already verified)
    email_info = database.user_emails.get_email_for_verification(
        test_tenant["id"], primary_email["id"]
    )

    with pytest.raises(ValidationError) as exc_info:
        emails_service.verify_email(
            test_tenant["id"],
            str(primary_email["id"]),
            str(test_user["id"]),
            email_info["verify_nonce"] if email_info else 12345,
        )

    assert exc_info.value.code == "already_verified"


def test_verify_email_invalid_nonce(test_tenant, test_user):
    """Test verifying email with wrong nonce returns ValidationError."""
    # Add unverified email
    new_email = f"verify-bad-nonce-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    with pytest.raises(ValidationError) as exc_info:
        emails_service.verify_email(
            test_tenant["id"],
            str(added["id"]),
            str(test_user["id"]),
            added["verify_nonce"] + 1,  # Wrong nonce
        )

    assert exc_info.value.code == "invalid_nonce"


# =============================================================================
# Resend Verification Tests
# =============================================================================


def test_resend_verification_as_self(test_tenant, test_user):
    """Test user can resend verification for their own email."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Add unverified email
    new_email = f"resend-self-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    result = emails_service.resend_verification(
        requesting_user, str(test_user["id"]), str(added["id"])
    )

    assert result["email"] == new_email
    assert "verify_nonce" in result
    assert "email_id" in result


def test_resend_verification_as_admin(test_tenant, test_admin_user, test_user):
    """Test admin can resend verification for any user's email."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Add unverified email
    new_email = f"resend-admin-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    result = emails_service.resend_verification(
        requesting_user, str(test_user["id"]), str(added["id"])
    )

    assert result["email"] == new_email
    assert "verify_nonce" in result


def test_resend_verification_forbidden_for_other_user(test_tenant, test_user, test_admin_user):
    """Test member cannot resend verification for other user's email."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Add email to admin
    new_email = f"resend-forbidden-{str(test_admin_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_admin_user["id"], new_email)

    with pytest.raises(ForbiddenError) as exc_info:
        emails_service.resend_verification(
            requesting_user, str(test_admin_user["id"]), str(added["id"])
        )

    assert exc_info.value.code == "email_access_denied"


def test_resend_verification_not_found(test_tenant, test_admin_user, test_user):
    """Test resending verification for non-existent email returns NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        emails_service.resend_verification(
            requesting_user,
            str(test_user["id"]),
            "00000000-0000-0000-0000-000000000000",
        )

    assert exc_info.value.code == "email_not_found"


# =============================================================================
# Utility Function Tests
# =============================================================================


def test_get_email_for_verification(test_tenant, test_user):
    """Test getting email info for verification flow."""
    # Add unverified email
    new_email = f"util-verify-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    result = emails_service.get_email_for_verification(test_tenant["id"], str(added["id"]))

    assert result is not None
    assert result["email"] == new_email
    assert "verify_nonce" in result


def test_get_email_for_verification_not_found(test_tenant):
    """Test getting verification info for non-existent email returns None."""
    result = emails_service.get_email_for_verification(
        test_tenant["id"],
        "00000000-0000-0000-0000-000000000000",
    )

    assert result is None


def test_get_primary_email(test_tenant, test_user):
    """Test getting primary email address."""
    result = emails_service.get_primary_email(test_tenant["id"], str(test_user["id"]))

    assert result == test_user["email"]


def test_get_primary_email_not_found(test_tenant):
    """Test getting primary email for non-existent user returns None."""
    result = emails_service.get_primary_email(
        test_tenant["id"],
        "00000000-0000-0000-0000-000000000000",
    )

    assert result is None


def test_get_email_address_by_id(test_tenant, test_user):
    """Test getting email address string by ID."""
    # Get user's email ID
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    email_id = str(emails[0]["id"])

    result = emails_service.get_email_address_by_id(
        test_tenant["id"], str(test_user["id"]), email_id
    )

    assert result == test_user["email"]


def test_get_email_address_by_id_not_found(test_tenant, test_user):
    """Test getting email by non-existent ID returns None."""
    result = emails_service.get_email_address_by_id(
        test_tenant["id"],
        test_user["id"],
        "00000000-0000-0000-0000-000000000000",
    )

    assert result is None


def test_get_user_with_primary_email(test_tenant, test_user):
    """Test getting user info with primary email."""
    result = emails_service.get_user_with_primary_email(test_tenant["id"], str(test_user["id"]))

    assert result is not None
    assert str(result["id"]) == str(test_user["id"])
    assert result["email"] == test_user["email"]


def test_get_user_with_primary_email_not_found(test_tenant):
    """Test getting user with primary email for non-existent user returns None."""
    result = emails_service.get_user_with_primary_email(
        test_tenant["id"],
        "00000000-0000-0000-0000-000000000000",
    )

    assert result is None


def test_verify_email_by_nonce_success(test_tenant, test_user):
    """Test public verification flow with correct nonce."""
    # Add unverified email
    new_email = f"verify-by-nonce-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    result = emails_service.verify_email_by_nonce(
        test_tenant["id"],
        str(added["id"]),
        added["verify_nonce"],
    )

    assert result is True

    # Verify email is now verified
    email = database.user_emails.get_email_by_id(test_tenant["id"], added["id"], test_user["id"])
    assert email["verified_at"] is not None


def test_verify_email_by_nonce_wrong_nonce(test_tenant, test_user):
    """Test public verification with wrong nonce returns False."""
    # Add unverified email
    new_email = f"verify-bad-{str(test_user['id'])[:8]}@example.com"
    added = _add_unverified_email(test_tenant["id"], test_user["id"], new_email)

    result = emails_service.verify_email_by_nonce(
        test_tenant["id"],
        str(added["id"]),
        added["verify_nonce"] + 1,  # Wrong nonce
    )

    assert result is False


def test_verify_email_by_nonce_not_found(test_tenant):
    """Test public verification for non-existent email returns False."""
    result = emails_service.verify_email_by_nonce(
        test_tenant["id"],
        "00000000-0000-0000-0000-000000000000",
        12345,
    )

    assert result is False


# =============================================================================
# check_routing_change
# =============================================================================


def test_check_routing_change_no_change_both_password(test_tenant, test_user):
    """Test no routing change when user has no IdP and domain has no binding."""
    result = emails_service.check_routing_change(
        test_tenant["id"], str(test_user["id"]), test_user["email"]
    )

    assert result is None


def test_check_routing_change_user_not_found(test_tenant):
    """Test returns None when user does not exist."""
    result = emails_service.check_routing_change(
        test_tenant["id"],
        "00000000-0000-0000-0000-000000000000",
        "test@example.com",
    )

    assert result is None


def test_check_routing_change_detects_idp_to_password(test_tenant, test_user, mocker):
    """Test detects routing change when user has IdP but new domain has no binding."""
    mocker.patch(
        "services.emails.database.users.get_user_by_id",
        return_value={
            "id": test_user["id"],
            "saml_idp_id": "idp-123",
            "saml_idp_name": "Okta Corporate",
        },
    )
    mocker.patch("services.emails.database.saml.get_idp_for_domain", return_value=None)

    result = emails_service.check_routing_change(
        test_tenant["id"], str(test_user["id"]), "user@unbound-domain.com"
    )

    assert result is not None
    assert result["current_idp_name"] == "Okta Corporate"
    assert result["new_idp_name"] == "Password authentication"


def test_check_routing_change_detects_password_to_idp(test_tenant, test_user, mocker):
    """Test detects routing change when user has no IdP but new domain is bound."""
    mocker.patch(
        "services.emails.database.users.get_user_by_id",
        return_value={
            "id": test_user["id"],
            "saml_idp_id": None,
            "saml_idp_name": None,
        },
    )
    mocker.patch(
        "services.emails.database.saml.get_idp_for_domain",
        return_value={"id": "idp-456", "name": "Google Workspace"},
    )

    result = emails_service.check_routing_change(
        test_tenant["id"], str(test_user["id"]), "user@google-domain.com"
    )

    assert result is not None
    assert result["current_idp_name"] == "Password authentication"
    assert result["new_idp_name"] == "Google Workspace"


def test_check_routing_change_no_change_same_idp(test_tenant, test_user, mocker):
    """Test no routing change when user and domain are on the same IdP."""
    mocker.patch(
        "services.emails.database.users.get_user_by_id",
        return_value={
            "id": test_user["id"],
            "saml_idp_id": "idp-123",
            "saml_idp_name": "Okta Corporate",
        },
    )
    mocker.patch(
        "services.emails.database.saml.get_idp_for_domain",
        return_value={"id": "idp-123", "name": "Okta Corporate"},
    )

    result = emails_service.check_routing_change(
        test_tenant["id"], str(test_user["id"]), "user@okta-domain.com"
    )

    assert result is None


# =============================================================================
# increment_set_password_nonce
# =============================================================================


def test_increment_set_password_nonce(test_tenant, test_user):
    """increment_set_password_nonce delegates to database layer."""
    import database

    tenant_id = test_tenant["id"]
    user_id = str(test_user["id"])

    # Get user's emails to find the primary email_id
    all_emails = database.user_emails.list_user_emails(tenant_id, user_id)
    primary = next(e for e in all_emails if e["is_primary"])
    email_id = str(primary["id"])

    # Should not raise
    emails_service.increment_set_password_nonce(tenant_id, email_id)


# =============================================================================
# list_users_by_ids_with_emails
# =============================================================================


def test_list_users_by_ids_with_emails(test_tenant, test_user):
    """Returns user list and secondary emails dict."""
    tenant_id = test_tenant["id"]
    user_id = str(test_user["id"])

    users, secondaries = emails_service.list_users_by_ids_with_emails(tenant_id, [user_id])

    assert len(users) >= 1
    found = any(str(u["id"]) == user_id for u in users)
    assert found
    # secondaries is a dict keyed by user_id
    assert isinstance(secondaries, dict)


def test_list_users_by_ids_with_emails_empty():
    """Empty user IDs returns empty results."""
    users, secondaries = emails_service.list_users_by_ids_with_emails("any-tenant", [])
    assert users == []
    assert secondaries == {}


# =============================================================================
# resolve_users_from_filter
# =============================================================================


def test_resolve_users_from_filter(test_tenant, test_user, mocker):
    """Resolves filter criteria into user IDs via the database."""
    tenant_id = test_tenant["id"]
    user_id = str(test_user["id"])

    mocker.patch(
        "services.emails.database.users.list_users",
        return_value=[{"id": user_id}],
    )

    result = emails_service.resolve_users_from_filter(
        tenant_id,
        roles=["member"],
    )

    assert user_id in result


def test_resolve_users_from_filter_empty(test_tenant, mocker):
    """Returns empty list when no users match."""
    mocker.patch(
        "services.emails.database.users.list_users",
        return_value=[],
    )

    result = emails_service.resolve_users_from_filter(
        test_tenant["id"],
        roles=["super_admin"],
        statuses=["anonymized"],
    )

    assert result == []
