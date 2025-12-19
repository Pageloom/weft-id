"""Tests for user inactivation and anonymization service layer functions."""

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.types import RequestingUser


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    """Helper to create RequestingUser from test fixture."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


# =============================================================================
# Inactivate User Tests
# =============================================================================


def test_inactivate_user_by_admin(test_tenant, test_admin_user, test_user):
    """Test that an admin can inactivate a regular user."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    result = users_service.inactivate_user(requesting_user, str(test_user["id"]))

    assert result.is_inactivated is True
    assert result.inactivated_at is not None


def test_inactivate_user_by_super_admin(test_tenant, test_super_admin_user, test_user):
    """Test that a super_admin can inactivate a regular user."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = users_service.inactivate_user(requesting_user, str(test_user["id"]))

    assert result.is_inactivated is True


def test_inactivate_user_by_member_fails(test_tenant, test_user, test_admin_user):
    """Test that a member cannot inactivate anyone."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.inactivate_user(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "admin_required"


def test_inactivate_self_fails(test_tenant, test_admin_user):
    """Test that a user cannot inactivate themselves."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.inactivate_user(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "self_inactivation"


def test_inactivate_nonexistent_user_fails(test_tenant, test_admin_user):
    """Test that inactivating a nonexistent user fails."""
    from uuid import uuid4

    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        users_service.inactivate_user(requesting_user, str(uuid4()))

    assert exc_info.value.code == "user_not_found"


def test_inactivate_already_inactivated_user_fails(test_tenant, test_admin_user, test_user):
    """Test that inactivating an already inactivated user fails."""
    import database
    from services import users as users_service

    # Inactivate the user directly in the database first
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.inactivate_user(requesting_user, str(test_user["id"]))

    assert exc_info.value.code == "already_inactivated"


def test_inactivate_service_user_fails(test_tenant, test_admin_user, b2b_oauth2_client):
    """Test that inactivating a service user fails."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.inactivate_user(requesting_user, str(b2b_oauth2_client["service_user_id"]))

    assert exc_info.value.code == "service_user_inactivation"


def test_inactivate_last_super_admin_fails(test_tenant, test_super_admin_user):
    """Test that inactivating the last super_admin fails."""
    from uuid import uuid4

    # Create a second super_admin to do the inactivation
    import database
    from services import users as users_service

    second_admin_id = str(uuid4())
    database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (id, tenant_id, first_name, last_name, role)
        VALUES (:id, :tenant_id, 'Second', 'Admin', 'super_admin')
        RETURNING id
        """,
        {"id": second_admin_id, "tenant_id": test_tenant["id"]},
    )

    requesting_user = RequestingUser(
        id=second_admin_id,
        tenant_id=test_tenant["id"],
        role="super_admin",
    )

    # Now inactivate the second admin
    users_service.inactivate_user(
        _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin"),
        second_admin_id,
    )

    # Now try to inactivate the last remaining super_admin (should fail)
    with pytest.raises(ValidationError) as exc_info:
        users_service.inactivate_user(requesting_user, str(test_super_admin_user["id"]))

    assert exc_info.value.code == "last_super_admin"


# =============================================================================
# Reactivate User Tests
# =============================================================================


def test_reactivate_user_by_admin(test_tenant, test_admin_user, test_user):
    """Test that an admin can reactivate an inactivated user."""
    import database
    from services import users as users_service

    # Inactivate the user first
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    result = users_service.reactivate_user(requesting_user, str(test_user["id"]))

    assert result.is_inactivated is False
    assert result.inactivated_at is None


def test_reactivate_user_by_member_fails(test_tenant, test_user, test_admin_user):
    """Test that a member cannot reactivate anyone."""
    import database
    from services import users as users_service

    # Inactivate the admin first
    database.users.inactivate_user(test_tenant["id"], test_admin_user["id"])

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.reactivate_user(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "admin_required"


def test_reactivate_active_user_fails(test_tenant, test_admin_user, test_user):
    """Test that reactivating an active user fails."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.reactivate_user(requesting_user, str(test_user["id"]))

    assert exc_info.value.code == "not_inactivated"


def test_reactivate_anonymized_user_fails(test_tenant, test_super_admin_user, test_user):
    """Test that reactivating an anonymized user fails."""
    import database
    from services import users as users_service

    # Anonymize the user first
    database.users.anonymize_user(test_tenant["id"], test_user["id"])

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.reactivate_user(requesting_user, str(test_user["id"]))

    assert exc_info.value.code == "anonymized_user"


# =============================================================================
# Anonymize User Tests
# =============================================================================


def test_anonymize_user_by_super_admin(test_tenant, test_super_admin_user, test_user):
    """Test that a super_admin can anonymize a user."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = users_service.anonymize_user(requesting_user, str(test_user["id"]))

    assert result.is_inactivated is True
    assert result.is_anonymized is True
    assert result.anonymized_at is not None
    assert result.first_name == "[Anonymized]"
    assert result.last_name == "User"


def test_anonymize_user_by_admin_fails(test_tenant, test_admin_user, test_user):
    """Test that an admin cannot anonymize a user."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        users_service.anonymize_user(requesting_user, str(test_user["id"]))

    assert exc_info.value.code == "super_admin_required"


def test_anonymize_self_fails(test_tenant, test_super_admin_user):
    """Test that a super_admin cannot anonymize themselves."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.anonymize_user(requesting_user, str(test_super_admin_user["id"]))

    assert exc_info.value.code == "self_anonymization"


def test_anonymize_already_anonymized_user_fails(test_tenant, test_super_admin_user, test_user):
    """Test that anonymizing an already anonymized user fails."""
    import database
    from services import users as users_service

    # Anonymize the user first
    database.users.anonymize_user(test_tenant["id"], test_user["id"])

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.anonymize_user(requesting_user, str(test_user["id"]))

    assert exc_info.value.code == "already_anonymized"


def test_anonymize_service_user_fails(test_tenant, test_super_admin_user, b2b_oauth2_client):
    """Test that anonymizing a service user fails."""
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(ValidationError) as exc_info:
        users_service.anonymize_user(requesting_user, str(b2b_oauth2_client["service_user_id"]))

    assert exc_info.value.code == "service_user_anonymization"


def test_anonymize_scrubs_email_addresses(test_tenant, test_super_admin_user, test_user):
    """Test that anonymizing a user scrubs their email addresses."""
    import database
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    users_service.anonymize_user(requesting_user, str(test_user["id"]))

    # Check that emails are anonymized
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    for email in emails:
        assert email["email"].startswith("anon-")
        assert email["email"].endswith("@anonymized.example.com")
        assert email["verified_at"] is None


def test_anonymize_deletes_mfa_data(test_tenant, test_super_admin_user, test_user):
    """Test that anonymizing a user deletes their MFA data."""
    import database
    from services import users as users_service

    # First set up some MFA data for the user
    database.mfa.create_totp_secret(
        test_tenant["id"],
        test_user["id"],
        "encrypted_secret",
        test_tenant["id"],
    )
    database.mfa.create_backup_code(
        test_tenant["id"],
        test_user["id"],
        "backup_code_hash",
        test_tenant["id"],
    )

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    users_service.anonymize_user(requesting_user, str(test_user["id"]))

    # Check that MFA data is deleted
    totp = database.mfa.get_totp_secret(test_tenant["id"], test_user["id"], "totp")
    assert totp is None

    backup_codes = database.mfa.list_backup_codes(test_tenant["id"], test_user["id"])
    assert len(backup_codes) == 0


# =============================================================================
# Authentication Blocking Tests
# =============================================================================


def test_inactivated_user_cannot_login(test_tenant, test_user):
    """Test that an inactivated user cannot log in."""
    import database
    from utils.auth import verify_login

    # Inactivate the user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Attempt to log in should return None
    result = verify_login(test_tenant["id"], test_user["email"], "TestPassword123!")
    assert result is None


def test_active_user_can_login(test_tenant, test_user):
    """Test that an active user can log in."""
    from utils.auth import verify_login

    result = verify_login(test_tenant["id"], test_user["email"], "TestPassword123!")
    assert result is not None
    assert result["id"] == test_user["id"]
