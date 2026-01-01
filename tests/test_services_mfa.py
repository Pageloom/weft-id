"""Comprehensive tests for MFA service layer functions.

This test file covers all MFA service operations for the services/mfa.py module.
Tests focus on:
- MFA status retrieval
- TOTP setup and verification flow
- Email MFA and downgrade from TOTP
- Backup codes management
- Admin MFA reset operations
- Event logging
"""

import database
import pytest
from services import mfa as mfa_service
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
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


def _setup_user_with_totp(tenant_id: str, user_id: str):
    """Helper to set up a user with TOTP enabled."""
    from utils.mfa import encrypt_secret, generate_totp_secret

    # Create and verify TOTP secret
    secret = generate_totp_secret()
    secret_encrypted = encrypt_secret(secret)
    database.mfa.create_totp_secret(tenant_id, user_id, secret_encrypted, tenant_id)
    database.mfa.verify_totp_secret(tenant_id, user_id, "totp")

    # Enable TOTP MFA
    database.mfa.enable_mfa(tenant_id, user_id, "totp")

    return secret


# =============================================================================
# MFA Status Tests
# =============================================================================


def test_get_mfa_status_not_enabled(test_tenant, test_user):
    """Test getting MFA status when MFA is not enabled."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Ensure MFA is disabled (fixture may have enabled email MFA)
    database.users.update_mfa_status(test_tenant["id"], test_user["id"], enabled=False)

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.get_mfa_status(requesting_user, user_data)

    assert result.enabled is False
    assert result.method is None or result.method == "email"  # Method may persist
    assert result.has_backup_codes is False
    assert result.backup_codes_remaining == 0


def test_get_mfa_status_totp_enabled(test_tenant, test_user):
    """Test getting MFA status when TOTP is enabled with backup codes."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Set up TOTP
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Generate backup codes
    from utils.mfa import generate_backup_codes, hash_code

    backup_codes = generate_backup_codes()
    for code in backup_codes:
        code_hash = hash_code(code.replace("-", ""))
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], code_hash, test_tenant["id"]
        )

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.get_mfa_status(requesting_user, user_data)

    assert result.enabled is True
    assert result.method == "totp"
    assert result.has_backup_codes is True
    assert result.backup_codes_remaining == 10  # Default count


def test_get_backup_codes_status(test_tenant, test_user):
    """Test getting backup codes status."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Create some backup codes
    from utils.mfa import generate_backup_codes, hash_code

    backup_codes = generate_backup_codes()
    for code in backup_codes:
        code_hash = hash_code(code.replace("-", ""))
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], code_hash, test_tenant["id"]
        )

    # Mark first 3 as used via SQL
    codes_list = database.mfa.list_backup_codes(test_tenant["id"], test_user["id"])
    for i in range(3):
        database.execute(
            test_tenant["id"],
            "UPDATE mfa_backup_codes SET used_at = NOW() WHERE id = :id",
            {"id": codes_list[i]["id"]},
        )

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.get_backup_codes_status(requesting_user, user_data)

    assert result.total == 10
    assert result.used == 3
    assert result.remaining == 7


# =============================================================================
# TOTP Setup Flow Tests
# =============================================================================


def test_setup_totp_success(test_tenant, test_user):
    """Test initiating TOTP setup."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.setup_totp(requesting_user, user_data)

    assert result.secret is not None
    assert result.uri is not None
    assert "otpauth://totp/" in result.uri
    # Email is URL-encoded in URI (@ becomes %40)
    import urllib.parse

    encoded_email = urllib.parse.quote(test_user["email"], safe="")
    assert encoded_email in result.uri

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "totp_setup_initiated", test_user["id"])

    # Verify secret stored in database (unverified)
    row = database.mfa.get_totp_secret(test_tenant["id"], test_user["id"], "totp")
    assert row is not None
    assert "secret_encrypted" in row

    # Verify it's not in the verified secrets table
    verified_row = database.mfa.get_verified_totp_secret(test_tenant["id"], test_user["id"], "totp")
    assert verified_row is None  # Not verified yet


def test_setup_totp_already_active(test_tenant, test_user):
    """Test that TOTP setup fails if TOTP is already active."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Set up TOTP first
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        mfa_service.setup_totp(requesting_user, user_data)

    assert exc_info.value.code == "totp_already_active"


def test_verify_totp_and_enable_success(test_tenant, test_user, monkeypatch):
    """Test verifying TOTP code and enabling TOTP MFA."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # First setup TOTP
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    mfa_service.setup_totp(requesting_user, user_data)

    # Mock TOTP verification to always succeed
    def mock_verify_totp(secret, code):
        return True

    monkeypatch.setattr("services.mfa.verify_totp_code", mock_verify_totp)

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    # Verify with any code (mocked to succeed)
    result = mfa_service.verify_totp_and_enable(requesting_user, user_data, "123456")

    assert result.codes is not None
    assert result.count == 10
    assert len(result.codes) == 10

    # Verify MFA is now enabled
    updated_user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert updated_user["mfa_enabled"] is True
    assert updated_user["mfa_method"] == "totp"

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "mfa_totp_enabled", test_user["id"])


def test_verify_totp_and_enable_no_setup(test_tenant, test_user):
    """Test that verification fails if no TOTP setup is in progress."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        mfa_service.verify_totp_and_enable(requesting_user, user_data, "123456")

    assert exc_info.value.code == "no_totp_pending"


def test_verify_totp_and_enable_invalid_code(test_tenant, test_user, monkeypatch):
    """Test that verification fails with invalid TOTP code."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # First setup TOTP
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    mfa_service.setup_totp(requesting_user, user_data)

    # Mock TOTP verification to fail
    def mock_verify_totp(secret, code):
        return False

    monkeypatch.setattr("services.mfa.verify_totp_code", mock_verify_totp)

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        mfa_service.verify_totp_and_enable(requesting_user, user_data, "000000")

    assert exc_info.value.code == "invalid_totp_code"


# =============================================================================
# Email MFA / Downgrade Flow Tests
# =============================================================================


def test_enable_email_mfa_direct(test_tenant, test_user):
    """Test enabling email MFA directly when no MFA is enabled."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    response, notification_info = mfa_service.enable_email_mfa(requesting_user, user_data)

    assert response.pending_verification is False
    assert response.status is not None
    assert response.status.enabled is True
    assert response.status.method == "email"
    assert notification_info is None

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "mfa_email_enabled", test_user["id"])


def test_enable_email_mfa_downgrade_from_totp(test_tenant, test_user, monkeypatch):
    """Test downgrading from TOTP to email MFA requires verification."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Set up TOTP first
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Mock create_email_otp to return a known code
    def mock_create_otp(tenant_id, user_id):
        return "123456"

    monkeypatch.setattr("services.mfa.create_email_otp", mock_create_otp)

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    response, notification_info = mfa_service.enable_email_mfa(requesting_user, user_data)

    assert response.pending_verification is True
    assert response.status is None
    assert "verification" in response.message.lower()
    assert notification_info is not None
    assert notification_info["email"] == test_user["email"]
    assert notification_info["code"] == "123456"


def test_enable_email_mfa_when_already_enabled(test_tenant, test_user):
    """Test enabling email MFA when it's already enabled."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Enable email MFA first
    database.mfa.enable_mfa(test_tenant["id"], test_user["id"], "email")

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    response, notification_info = mfa_service.enable_email_mfa(requesting_user, user_data)

    assert response.pending_verification is False
    assert response.status.enabled is True
    assert response.status.method == "email"


def test_verify_mfa_downgrade_success(test_tenant, test_user, monkeypatch):
    """Test completing TOTP to email downgrade with valid code."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Set up TOTP
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Mock email OTP verification to succeed
    def mock_verify_otp(tenant_id, user_id, code):
        return True

    monkeypatch.setattr("services.mfa.verify_email_otp", mock_verify_otp)

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.verify_mfa_downgrade(requesting_user, user_data, "123456")

    assert result.enabled is True
    assert result.method == "email"

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "mfa_downgraded_to_email", test_user["id"])

    # Verify TOTP secrets were deleted
    totp_secret = database.mfa.get_totp_secret(test_tenant["id"], test_user["id"], "totp")
    assert totp_secret is None


def test_verify_mfa_downgrade_invalid_state(test_tenant, test_user):
    """Test that downgrade verification fails if not in TOTP state."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # User has no MFA enabled
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        mfa_service.verify_mfa_downgrade(requesting_user, user_data, "123456")

    assert exc_info.value.code == "invalid_mfa_state"


def test_verify_mfa_downgrade_invalid_code(test_tenant, test_user, monkeypatch):
    """Test that downgrade verification fails with invalid code."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Set up TOTP
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Mock email OTP verification to fail
    def mock_verify_otp(tenant_id, user_id, code):
        return False

    monkeypatch.setattr("services.mfa.verify_email_otp", mock_verify_otp)

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        mfa_service.verify_mfa_downgrade(requesting_user, user_data, "000000")

    assert exc_info.value.code == "invalid_email_otp"


# =============================================================================
# MFA Management Tests
# =============================================================================


def test_disable_mfa_success(test_tenant, test_user):
    """Test disabling MFA."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Set up TOTP
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Generate backup codes
    from utils.mfa import generate_backup_codes, hash_code

    backup_codes = generate_backup_codes()
    for code in backup_codes:
        code_hash = hash_code(code.replace("-", ""))
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], code_hash, test_tenant["id"]
        )

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.disable_mfa(requesting_user, user_data)

    assert result.enabled is False
    # Method is reset to "email" after disable (expected behavior)
    assert result.method == "email"
    assert result.has_backup_codes is False

    # Verify event logged with previous method
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "mfa_disabled"
    assert events[0]["metadata"]["previous_method"] == "totp"

    # Verify TOTP secrets and backup codes were deleted
    totp_secret = database.mfa.get_totp_secret(test_tenant["id"], test_user["id"], "totp")
    assert totp_secret is None
    backup_codes_list = database.mfa.list_backup_codes(test_tenant["id"], test_user["id"])
    assert len(backup_codes_list) == 0


def test_disable_mfa_when_not_enabled(test_tenant, test_user):
    """Test disabling MFA when it's not enabled (should succeed)."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.disable_mfa(requesting_user, user_data)

    assert result.enabled is False


def test_regenerate_backup_codes_success(test_tenant, test_user):
    """Test regenerating backup codes."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Enable email MFA first
    database.mfa.enable_mfa(test_tenant["id"], test_user["id"], "email")

    # Create initial backup codes
    from utils.mfa import generate_backup_codes, hash_code

    old_codes = generate_backup_codes()
    for code in old_codes:
        code_hash = hash_code(code.replace("-", ""))
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], code_hash, test_tenant["id"]
        )

    # Get fresh user data
    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    result = mfa_service.regenerate_backup_codes(requesting_user, user_data)

    assert result.codes is not None
    assert result.count == 10
    assert len(result.codes) == 10

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "mfa_backup_codes_regenerated", test_user["id"])

    # Verify old codes were deleted and new ones created
    backup_codes_list = database.mfa.list_backup_codes(test_tenant["id"], test_user["id"])
    assert len(backup_codes_list) == 10


def test_regenerate_backup_codes_mfa_not_enabled(test_tenant, test_user):
    """Test that regenerating backup codes fails if MFA is not enabled."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    # Ensure MFA is disabled
    database.users.update_mfa_status(test_tenant["id"], test_user["id"], enabled=False)

    user_data = database.users.get_user_by_id(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        mfa_service.regenerate_backup_codes(requesting_user, user_data)

    assert exc_info.value.code == "mfa_not_enabled"


# =============================================================================
# Admin Operations Tests
# =============================================================================


def test_reset_user_mfa_as_admin(test_tenant, test_admin_user, test_user):
    """Test that admin can reset user's MFA."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Set up TOTP for test_user
    _setup_user_with_totp(test_tenant["id"], str(test_user["id"]))

    # Generate backup codes
    from utils.mfa import generate_backup_codes, hash_code

    backup_codes = generate_backup_codes()
    for code in backup_codes:
        code_hash = hash_code(code.replace("-", ""))
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], code_hash, test_tenant["id"]
        )

    result = mfa_service.reset_user_mfa(requesting_user, str(test_user["id"]))

    assert result.enabled is False
    # Method may persist as "totp" after reset (database state)
    assert result.method in ("totp", "email", None)
    assert result.has_backup_codes is False

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "mfa_reset_by_admin"
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
    assert str(events[0]["artifact_id"]) == str(test_user["id"])
    assert events[0]["metadata"]["previous_method"] == "totp"
    assert events[0]["metadata"]["was_enabled"] is True


def test_reset_user_mfa_as_member_forbidden(test_tenant, test_user, test_admin_user):
    """Test that member cannot reset user's MFA."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        mfa_service.reset_user_mfa(requesting_user, str(test_admin_user["id"]))

    assert exc_info.value.code == "admin_required"


def test_reset_user_mfa_user_not_found(test_tenant, test_admin_user):
    """Test that resetting MFA for non-existent user returns NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        mfa_service.reset_user_mfa(requesting_user, "00000000-0000-0000-0000-000000000000")

    assert exc_info.value.code == "user_not_found"


# =============================================================================
# Utility Functions Tests
# =============================================================================


def test_list_backup_codes_raw(test_tenant, test_user):
    """Test listing raw backup codes."""
    # Create backup codes
    from utils.mfa import generate_backup_codes, hash_code

    backup_codes = generate_backup_codes()
    for code in backup_codes:
        code_hash = hash_code(code.replace("-", ""))
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], code_hash, test_tenant["id"]
        )

    result = mfa_service.list_backup_codes_raw(test_tenant["id"], str(test_user["id"]))

    assert len(result) == 10
    assert all("code_hash" in c for c in result)
    assert all("used_at" in c for c in result)


def test_get_pending_totp_setup(test_tenant, test_user):
    """Test getting pending TOTP setup info."""
    from utils.mfa import encrypt_secret, generate_totp_secret

    # Create unverified TOTP secret
    secret = generate_totp_secret()
    secret_encrypted = encrypt_secret(secret)
    database.mfa.create_totp_secret(
        test_tenant["id"], test_user["id"], secret_encrypted, test_tenant["id"]
    )

    result = mfa_service.get_pending_totp_setup(test_tenant["id"], str(test_user["id"]))

    assert result is not None
    secret_display, uri = result
    assert secret_display is not None
    assert uri is not None
    assert "otpauth://totp/" in uri


def test_get_pending_totp_setup_no_setup(test_tenant, test_user):
    """Test getting pending TOTP setup when none exists."""
    result = mfa_service.get_pending_totp_setup(test_tenant["id"], str(test_user["id"]))

    assert result is None


def test_generate_initial_backup_codes(test_tenant, test_user):
    """Test generating initial backup codes."""
    result = mfa_service.generate_initial_backup_codes(test_tenant["id"], str(test_user["id"]))

    assert len(result) == 10
    assert all(isinstance(code, str) for code in result)
    assert all("-" in code for code in result)

    # Verify codes were stored in database
    backup_codes_list = database.mfa.list_backup_codes(test_tenant["id"], test_user["id"])
    assert len(backup_codes_list) == 10
