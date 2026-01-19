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


# =============================================================================
# Event Logging Tests
# =============================================================================


def test_inactivate_user_logs_event(test_tenant, test_admin_user, test_user):
    """Test that inactivating a user logs an event."""
    import database
    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    users_service.inactivate_user(requesting_user, str(test_user["id"]))

    # Verify event was logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == "user_inactivated"
    assert str(events[0]["artifact_id"]) == str(test_user["id"])
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])


def test_inactivate_user_revokes_oauth_tokens(
    test_tenant, test_admin_user, test_user, normal_oauth2_client
):
    """Test that inactivating a user revokes their OAuth tokens."""
    import database
    from services import users as users_service

    # Create an OAuth token for the user
    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        parent_token_id=refresh_token_id,
    )

    # Verify tokens are valid before inactivation
    assert database.oauth2.validate_token(access_token, test_tenant["id"]) is not None

    # Inactivate the user
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    users_service.inactivate_user(requesting_user, str(test_user["id"]))

    # Verify tokens are now revoked
    assert database.oauth2.validate_token(access_token, test_tenant["id"]) is None
    assert (
        database.oauth2.validate_refresh_token(
            test_tenant["id"], refresh_token, normal_oauth2_client["id"]
        )
        is None
    )


def test_reactivate_user_logs_event(test_tenant, test_admin_user, test_user):
    """Test that reactivating a user logs an event."""
    import database
    from services import users as users_service

    # Inactivate the user first
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    users_service.reactivate_user(requesting_user, str(test_user["id"]))

    # Verify event was logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == "user_reactivated"
    assert str(events[0]["artifact_id"]) == str(test_user["id"])


def test_reactivate_user_clears_reactivation_denied(test_tenant, test_admin_user, test_user):
    """Test that reactivating a user clears the reactivation_denied_at flag."""
    import database
    from services import users as users_service

    # Inactivate and deny reactivation
    database.users.inactivate_user(test_tenant["id"], test_user["id"])
    database.users.set_reactivation_denied(test_tenant["id"], test_user["id"])

    # Verify the flag is set
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user["reactivation_denied_at"] is not None

    # Reactivate the user
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    users_service.reactivate_user(requesting_user, str(test_user["id"]))

    # Verify the flag is cleared
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user["reactivation_denied_at"] is None


def test_self_reactivate_super_admin_success(test_tenant, test_super_admin_user):
    """Test that a super admin can self-reactivate their account."""
    import database
    from services import users as users_service

    # Inactivate the super admin
    database.users.inactivate_user(test_tenant["id"], test_super_admin_user["id"])

    # Verify user is inactivated
    user = database.users.get_user_by_id(test_tenant["id"], test_super_admin_user["id"])
    assert user["is_inactivated"] is True

    # Self-reactivate
    users_service.self_reactivate_super_admin(
        tenant_id=test_tenant["id"],
        user_id=str(test_super_admin_user["id"]),
    )

    # Verify user is reactivated
    user = database.users.get_user_by_id(test_tenant["id"], test_super_admin_user["id"])
    assert user["is_inactivated"] is False


def test_self_reactivate_non_super_admin_forbidden(test_tenant, test_admin_user):
    """Test that non-super admins cannot self-reactivate."""
    import database
    from services import users as users_service
    from services.exceptions import ForbiddenError

    # Inactivate the admin
    database.users.inactivate_user(test_tenant["id"], test_admin_user["id"])

    # Attempt self-reactivation should fail
    with pytest.raises(ForbiddenError) as exc_info:
        users_service.self_reactivate_super_admin(
            tenant_id=test_tenant["id"],
            user_id=str(test_admin_user["id"]),
        )
    assert exc_info.value.code == "super_admin_required"


def test_self_reactivate_active_user_validation_error(test_tenant, test_super_admin_user):
    """Test that attempting to self-reactivate an active user fails."""
    from services import users as users_service
    from services.exceptions import ValidationError

    # Attempt self-reactivation of active user should fail
    with pytest.raises(ValidationError) as exc_info:
        users_service.self_reactivate_super_admin(
            tenant_id=test_tenant["id"],
            user_id=str(test_super_admin_user["id"]),
        )
    assert exc_info.value.code == "not_inactivated"


def test_self_reactivate_anonymized_user_validation_error(test_tenant, test_super_admin_user):
    """Test that attempting to self-reactivate an anonymized user fails."""
    import database
    from services import users as users_service
    from services.exceptions import ValidationError

    # Anonymize the super admin
    database.users.anonymize_user(test_tenant["id"], test_super_admin_user["id"])

    # Attempt self-reactivation should fail
    with pytest.raises(ValidationError) as exc_info:
        users_service.self_reactivate_super_admin(
            tenant_id=test_tenant["id"],
            user_id=str(test_super_admin_user["id"]),
        )
    assert exc_info.value.code == "user_anonymized"


def test_self_reactivate_logs_event(test_tenant, test_super_admin_user):
    """Test that super admin self-reactivation logs an event."""
    import database
    from services import users as users_service

    # Inactivate the super admin
    database.users.inactivate_user(test_tenant["id"], test_super_admin_user["id"])

    # Self-reactivate
    users_service.self_reactivate_super_admin(
        tenant_id=test_tenant["id"],
        user_id=str(test_super_admin_user["id"]),
    )

    # Verify event was logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == "super_admin_self_reactivated"
    assert str(events[0]["artifact_id"]) == str(test_super_admin_user["id"])
    assert str(events[0]["actor_user_id"]) == str(test_super_admin_user["id"])


def test_anonymize_user_logs_event_with_metadata(test_tenant, test_super_admin_user, test_user):
    """Test that anonymizing a user logs an event with pre-anonymization metadata."""
    import database
    from services import users as users_service

    # Capture user info before anonymization
    user_before = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    primary_email = database.user_emails.get_primary_email(test_tenant["id"], test_user["id"])

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    users_service.anonymize_user(requesting_user, str(test_user["id"]))

    # Verify event was logged with pre-anonymization info
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == "user_anonymized"
    assert str(events[0]["artifact_id"]) == str(test_user["id"])

    # Verify metadata contains pre-anonymization info
    metadata = events[0]["metadata"]
    assert (
        metadata["anonymized_user_name"]
        == f"{user_before['first_name']} {user_before['last_name']}"
    )
    assert metadata["anonymized_user_email"] == primary_email["email"]
    assert metadata["anonymized_user_role"] == user_before["role"]


def test_reactivate_nonexistent_user_fails(test_tenant, test_admin_user):
    """Test that reactivating a nonexistent user fails."""
    from uuid import uuid4

    from services import users as users_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        users_service.reactivate_user(requesting_user, str(uuid4()))

    assert exc_info.value.code == "user_not_found"


# =============================================================================
# Password Preservation E2E Tests
# =============================================================================


def test_super_admin_self_reactivate_preserves_password(test_tenant, test_super_admin_user):
    """E2E: Super admin with password → inactivated → self-reactivate → password preserved."""
    import database
    from services import users as users_service
    from utils.password import hash_password, verify_password

    tenant_id = str(test_tenant["id"])
    user_id = str(test_super_admin_user["id"])

    # Step 1: Set a password for the super admin
    original_password = "super_admin_secure_pw_456"
    password_hash = hash_password(original_password)
    database.users.update_password(tenant_id, user_id, password_hash)

    # Verify super admin has password
    user_before = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_before["has_password"] is True
    assert user_before["is_inactivated"] is False

    # Step 2: Inactivate the super admin
    database.users.inactivate_user(tenant_id, user_id)

    # Verify inactivated but password still exists (in DB)
    user_inactivated = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_inactivated["is_inactivated"] is True
    assert user_inactivated["has_password"] is True

    # Step 3: Super admin self-reactivates
    users_service.self_reactivate_super_admin(tenant_id, user_id)

    # Verify reactivated with password intact
    user_after = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_after["is_inactivated"] is False
    assert user_after["has_password"] is True

    # Step 4: Verify the password still validates correctly
    from database._core import fetchone

    user_with_hash = fetchone(
        tenant_id,
        "select password_hash from users where id = :user_id",
        {"user_id": user_id},
    )
    assert user_with_hash["password_hash"] is not None
    assert verify_password(user_with_hash["password_hash"], original_password) is True


def test_jit_user_reactivated_has_no_password(test_tenant, test_admin_user):
    """E2E: JIT user (no password) → inactivated → reactivated → still has no password."""
    import database
    from services import users as users_service

    tenant_id = str(test_tenant["id"])

    # Step 1: Create a JIT-like user (no password set)
    result = database.users.create_user(
        tenant_id,
        tenant_id,
        "JIT",
        "User",
        f"jit_user_{tenant_id[:8]}@example.com",
        "member",
    )
    jit_user_id = str(result["user_id"])

    # Verify user has no password (simulating JIT provisioning)
    user_before = database.users.get_user_with_saml_info(tenant_id, jit_user_id)
    assert user_before["has_password"] is False
    assert user_before["is_inactivated"] is False

    # Step 2: Inactivate the JIT user
    database.users.inactivate_user(tenant_id, jit_user_id)

    user_inactivated = database.users.get_user_with_saml_info(tenant_id, jit_user_id)
    assert user_inactivated["is_inactivated"] is True
    assert user_inactivated["has_password"] is False

    # Step 3: Admin reactivates the JIT user
    requesting_user = _make_requesting_user(test_admin_user, tenant_id, "admin")
    users_service.reactivate_user(requesting_user, jit_user_id)

    # Step 4: Verify user is active but still has no password
    user_after = database.users.get_user_with_saml_info(tenant_id, jit_user_id)
    assert user_after["is_inactivated"] is False
    assert (
        user_after["has_password"] is False
    )  # Still no password - must go through set-password flow


def test_admin_reactivate_idp_disconnected_user_preserves_password(
    test_tenant, test_super_admin_user, test_admin_user, test_user
):
    """E2E: User with password -> IdP -> disconnect (inactivated) -> admin reactivates -> password works.

    This tests the full password retention flow through IdP lifecycle:
    1. User has a password
    2. User is assigned to an IdP (password preserved but unusable)
    3. User is disconnected from IdP (triggers automatic inactivation)
    4. Admin reactivates user
    5. Password still works for authentication
    """
    import database
    from database._core import fetchone
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services import users as users_service
    from utils.password import hash_password, verify_password

    tenant_id = str(test_tenant["id"])
    super_admin_requesting = _make_requesting_user(test_super_admin_user, tenant_id, "super_admin")
    admin_requesting = _make_requesting_user(test_admin_user, tenant_id, "admin")
    user_id = str(test_user["id"])

    # Step 1: Set a password for the user
    original_password = "my_secure_password_456"
    password_hash = hash_password(original_password)
    database.users.update_password(tenant_id, user_id, password_hash)

    # Verify user has password and is active
    user_step1 = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_step1["has_password"] is True
    assert user_step1["is_inactivated"] is False
    assert user_step1["saml_idp_id"] is None

    # Step 2: Create IdP and assign user
    idp_data = IdPCreate(
        name="Test IdP for Retention",
        provider_type="generic",
        entity_id="https://idp.example.com/retention-test",
        sso_url="https://idp.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2S1jzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
5a3PZp7bLrvI0w0D6oRMU6EqE5H5p5n0S5N1T2CPXQ5V6mWg1G1L3eSmpV6NLGKl
xpJ1NKT9GvMNJoEFvb0q5Nz5KqzJrL8N1SvOJ4x7L2qK8LZ5mNT8w0VPpSCR5N0Z
q4Z3BwH1GcKm3LMJ1Pk3Xn5xKvKxmy5r+U5BQnJk5g8s4wnVwbLhFCzYhB5CZ2z6
c6q5b+E6b7q8qrPCxLLPQa9LxmpRbqHp6+U5PvAqC3FkP8QJ7LmEqlM6bB2N7o5j
BvqJl2E5m6lyLBwNVXthLWP5k1LRE7V8LhqN5m1nmU1P5MBXD7k2Pn8R1xab4Lnm
F6q1y5P5E6mJ+X6qAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA==
-----END CERTIFICATE-----""",
        is_enabled=True,
    )
    idp = saml_service.create_identity_provider(
        super_admin_requesting, idp_data, "https://test.example.com"
    )
    saml_service.assign_user_idp(super_admin_requesting, user_id, idp.id)

    # Verify user has IdP, password preserved
    user_step2 = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_step2["saml_idp_id"] is not None
    assert user_step2["has_password"] is True  # Password preserved!
    assert user_step2["is_inactivated"] is False

    # Step 3: Disconnect user from IdP (triggers automatic inactivation)
    saml_service.assign_user_idp(super_admin_requesting, user_id, None)

    # Verify user is inactivated but password is preserved
    user_step3 = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_step3["saml_idp_id"] is None
    assert user_step3["is_inactivated"] is True
    assert user_step3["has_password"] is True  # Password still preserved!

    # Step 4: Admin reactivates the user
    users_service.reactivate_user(admin_requesting, user_id)

    # Verify user is active with password intact
    user_step4 = database.users.get_user_with_saml_info(tenant_id, user_id)
    assert user_step4["is_inactivated"] is False
    assert user_step4["has_password"] is True

    # Step 5: Verify the password actually validates correctly
    user_with_hash = fetchone(
        tenant_id,
        "select password_hash from users where id = :user_id",
        {"user_id": user_id},
    )
    assert user_with_hash["password_hash"] is not None
    assert verify_password(user_with_hash["password_hash"], original_password) is True
