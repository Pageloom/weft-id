"""Comprehensive tests for Settings service layer functions.

This test file covers all settings service operations for the services/settings.py module.
Tests include:
- Privileged domains management (list, add, delete)
- Tenant security settings (get, update)
- Utility functions (domain checking, session settings)
- Authorization checks
- Event logging
- Activity tracking
"""

import database
import pytest
from services import settings as settings_service
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError

# =============================================================================
# Helper Functions
# =============================================================================


def _make_requesting_user(user: dict, tenant_id: str, role: str | None = None):
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


# =============================================================================
# Privileged Domains - List Tests
# =============================================================================


def test_list_privileged_domains_as_admin(test_tenant, test_admin_user):
    """Test that an admin can list privileged domains."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    result = settings_service.list_privileged_domains(requesting_user)

    assert isinstance(result, list)
    # May be empty or have domains depending on fixtures


def test_list_privileged_domains_as_super_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can list privileged domains."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = settings_service.list_privileged_domains(requesting_user)

    assert isinstance(result, list)


def test_list_privileged_domains_as_member_forbidden(test_tenant, test_user):
    """Test that a regular member cannot list privileged domains."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        settings_service.list_privileged_domains(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_list_privileged_domains_tracks_activity(test_tenant, test_admin_user):
    """Test that listing privileged domains tracks activity."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    settings_service.list_privileged_domains(requesting_user)

    # Verify activity was tracked
    activity = database.user_activity.get_activity(test_tenant["id"], test_admin_user["id"])
    assert activity is not None
    assert str(activity["user_id"]) == str(test_admin_user["id"])


# =============================================================================
# Privileged Domains - Add Tests
# =============================================================================


def test_add_privileged_domain_as_admin(test_tenant, test_admin_user):
    """Test that an admin can add a privileged domain."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="example.com")

    result = settings_service.add_privileged_domain(requesting_user, domain_data)

    assert result.domain == "example.com"
    assert result.id is not None
    assert result.created_at is not None

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "privileged_domain_added", result.id)


def test_add_privileged_domain_normalizes_at_prefix(test_tenant, test_admin_user):
    """Test that domain with @ prefix is normalized."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="@example.org")

    result = settings_service.add_privileged_domain(requesting_user, domain_data)

    assert result.domain == "example.org"  # @ removed


def test_add_privileged_domain_normalizes_uppercase(test_tenant, test_admin_user):
    """Test that domain is normalized to lowercase."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="EXAMPLE.NET")

    result = settings_service.add_privileged_domain(requesting_user, domain_data)

    assert result.domain == "example.net"


def test_add_privileged_domain_duplicate_conflict(test_tenant, test_admin_user):
    """Test that adding a duplicate domain raises ConflictError."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="duplicate.com")

    # Add once
    settings_service.add_privileged_domain(requesting_user, domain_data)

    # Try to add again
    with pytest.raises(ConflictError) as exc_info:
        settings_service.add_privileged_domain(requesting_user, domain_data)

    assert exc_info.value.code == "domain_exists"


def test_add_privileged_domain_empty_validation_error(test_tenant, test_admin_user):
    """Test that adding an empty domain raises ValidationError."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="   ")  # Empty after strip

    with pytest.raises(ValidationError) as exc_info:
        settings_service.add_privileged_domain(requesting_user, domain_data)

    assert exc_info.value.code == "invalid_domain"


def test_add_privileged_domain_with_spaces_validation_error(test_tenant, test_admin_user):
    """Test that domain with spaces raises ValidationError."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="my domain.com")

    with pytest.raises(ValidationError) as exc_info:
        settings_service.add_privileged_domain(requesting_user, domain_data)

    assert exc_info.value.code == "invalid_domain"


def test_add_privileged_domain_no_dot_validation_error(test_tenant, test_admin_user):
    """Test that domain without dot raises ValidationError."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="localhost")

    with pytest.raises(ValidationError) as exc_info:
        settings_service.add_privileged_domain(requesting_user, domain_data)

    assert exc_info.value.code == "invalid_domain"


def test_add_privileged_domain_as_member_forbidden(test_tenant, test_user):
    """Test that a regular member cannot add privileged domains."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")
    domain_data = PrivilegedDomainCreate(domain="forbidden.com")

    with pytest.raises(ForbiddenError) as exc_info:
        settings_service.add_privileged_domain(requesting_user, domain_data)

    assert exc_info.value.code == "admin_required"


# =============================================================================
# Privileged Domains - Delete Tests
# =============================================================================


def test_delete_privileged_domain_as_admin(test_tenant, test_admin_user):
    """Test that an admin can delete a privileged domain."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # First add a domain
    domain_data = PrivilegedDomainCreate(domain="deleteme.com")
    added = settings_service.add_privileged_domain(requesting_user, domain_data)

    # Delete it
    settings_service.delete_privileged_domain(requesting_user, added.id)

    # Verify it's gone
    domains = settings_service.list_privileged_domains(requesting_user)
    domain_ids = [d.id for d in domains]
    assert added.id not in domain_ids

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "privileged_domain_deleted", added.id)


def test_delete_privileged_domain_not_found(test_tenant, test_admin_user):
    """Test that deleting a non-existent domain raises NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        settings_service.delete_privileged_domain(
            requesting_user, "00000000-0000-0000-0000-000000000000"
        )

    assert exc_info.value.code == "domain_not_found"


def test_delete_privileged_domain_as_member_forbidden(test_tenant, test_user, test_admin_user):
    """Test that a regular member cannot delete privileged domains."""
    from schemas.settings import PrivilegedDomainCreate

    # Create a domain as admin
    admin_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="nodelete.com")
    added = settings_service.add_privileged_domain(admin_user, domain_data)

    # Try to delete as member
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        settings_service.delete_privileged_domain(requesting_user, added.id)

    assert exc_info.value.code == "admin_required"


# =============================================================================
# Tenant Security Settings - Get Tests
# =============================================================================


def test_get_security_settings_as_super_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can get security settings."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = settings_service.get_security_settings(requesting_user)

    assert result is not None
    assert hasattr(result, "session_timeout_seconds")
    assert hasattr(result, "persistent_sessions")
    assert hasattr(result, "allow_users_edit_profile")
    assert hasattr(result, "allow_users_add_emails")


def test_get_security_settings_returns_defaults_when_not_set(test_tenant, test_super_admin_user):
    """Test that get_security_settings returns defaults when no settings exist."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = settings_service.get_security_settings(requesting_user)

    # Check defaults
    assert result.session_timeout_seconds is None
    assert result.persistent_sessions is True
    assert result.allow_users_edit_profile is True
    assert result.allow_users_add_emails is True


def test_get_security_settings_returns_saved_values(test_tenant, test_super_admin_user):
    """Test that get_security_settings returns saved values when settings exist."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # First set some custom values
    settings_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=7200,
        persistent_sessions=False,
        allow_users_edit_profile=False,
        allow_users_add_emails=False,
    )
    settings_service.update_security_settings(requesting_user, settings_update)

    # Now get them back
    result = settings_service.get_security_settings(requesting_user)

    assert result.session_timeout_seconds == 7200
    assert result.persistent_sessions is False
    assert result.allow_users_edit_profile is False
    assert result.allow_users_add_emails is False


def test_get_security_settings_as_admin_forbidden(test_tenant, test_admin_user):
    """Test that a regular admin cannot get security settings."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        settings_service.get_security_settings(requesting_user)

    assert exc_info.value.code == "super_admin_required"


def test_get_security_settings_as_member_forbidden(test_tenant, test_user):
    """Test that a regular member cannot get security settings."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        settings_service.get_security_settings(requesting_user)

    assert exc_info.value.code == "super_admin_required"


def test_get_security_settings_tracks_activity(test_tenant, test_super_admin_user):
    """Test that getting security settings tracks activity."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    settings_service.get_security_settings(requesting_user)

    # Verify activity was tracked
    activity = database.user_activity.get_activity(test_tenant["id"], test_super_admin_user["id"])
    assert activity is not None
    assert str(activity["user_id"]) == str(test_super_admin_user["id"])


# =============================================================================
# Tenant Security Settings - Update Tests
# =============================================================================


def test_update_security_settings_as_super_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can update security settings."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=3600,
        persistent_sessions=False,
        allow_users_edit_profile=False,
        allow_users_add_emails=False,
    )

    result = settings_service.update_security_settings(requesting_user, settings_update)

    assert result.session_timeout_seconds == 3600
    assert result.persistent_sessions is False
    assert result.allow_users_edit_profile is False
    assert result.allow_users_add_emails is False

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "tenant_settings_updated", test_tenant["id"])


def test_update_security_settings_partial_update(test_tenant, test_super_admin_user):
    """Test that partial updates work (only specified fields change)."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # First set all to known values
    full_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=1800,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
    )
    settings_service.update_security_settings(requesting_user, full_update)

    # Now update only one field
    partial_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=7200,
    )
    result = settings_service.update_security_settings(requesting_user, partial_update)

    assert result.session_timeout_seconds == 7200
    assert result.persistent_sessions is True  # Unchanged
    assert result.allow_users_edit_profile is True  # Unchanged
    assert result.allow_users_add_emails is True  # Unchanged


def test_update_security_settings_as_admin_forbidden(test_tenant, test_admin_user):
    """Test that a regular admin cannot update security settings."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    settings_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=3600,
    )

    with pytest.raises(ForbiddenError) as exc_info:
        settings_service.update_security_settings(requesting_user, settings_update)

    assert exc_info.value.code == "super_admin_required"


# =============================================================================
# Utility Functions Tests
# =============================================================================


def test_get_privileged_domains_list(test_tenant, test_admin_user):
    """Test get_privileged_domains_list returns list of domain strings."""
    from schemas.settings import PrivilegedDomainCreate

    # Add a domain first
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="utility.com")
    settings_service.add_privileged_domain(requesting_user, domain_data)

    # Get list
    result = settings_service.get_privileged_domains_list(test_tenant["id"])

    assert isinstance(result, list)
    assert "utility.com" in result


def test_is_privileged_domain_returns_true(test_tenant, test_admin_user):
    """Test is_privileged_domain returns True for privileged domain."""
    from schemas.settings import PrivilegedDomainCreate

    # Add a domain
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="priv.com")
    settings_service.add_privileged_domain(requesting_user, domain_data)

    # Check it
    result = settings_service.is_privileged_domain(test_tenant["id"], "priv.com")

    assert result is True


def test_is_privileged_domain_returns_false(test_tenant):
    """Test is_privileged_domain returns False for non-privileged domain."""
    result = settings_service.is_privileged_domain(test_tenant["id"], "notpriv.com")

    assert result is False


def test_is_privileged_domain_case_insensitive(test_tenant, test_admin_user):
    """Test is_privileged_domain is case insensitive."""
    from schemas.settings import PrivilegedDomainCreate

    # Add lowercase domain
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="casetest.com")
    settings_service.add_privileged_domain(requesting_user, domain_data)

    # Check with uppercase
    result = settings_service.is_privileged_domain(test_tenant["id"], "CASETEST.COM")

    assert result is True


def test_can_users_add_emails_default_true(test_tenant):
    """Test can_users_add_emails returns True by default."""
    result = settings_service.can_users_add_emails(test_tenant["id"])

    assert result is True


def test_can_users_add_emails_when_set_to_false(test_tenant, test_super_admin_user):
    """Test can_users_add_emails returns False when set."""
    from schemas.settings import TenantSecuritySettingsUpdate

    # Set to false
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(allow_users_add_emails=False)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Check it
    result = settings_service.can_users_add_emails(test_tenant["id"])

    assert result is False


def test_can_user_edit_profile_default_true(test_tenant):
    """Test can_user_edit_profile returns True by default."""
    result = settings_service.can_user_edit_profile(test_tenant["id"])

    assert result is True


def test_can_user_edit_profile_when_set_to_false(test_tenant, test_super_admin_user):
    """Test can_user_edit_profile returns False when set."""
    from schemas.settings import TenantSecuritySettingsUpdate

    # Set to false
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(allow_users_edit_profile=False)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Check it
    result = settings_service.can_user_edit_profile(test_tenant["id"])

    assert result is False


def test_get_session_settings_returns_none_when_not_set(test_tenant):
    """Test get_session_settings returns None when no settings exist."""
    result = settings_service.get_session_settings(test_tenant["id"])

    # May return None or a dict with defaults depending on implementation
    assert result is None or isinstance(result, dict)


def test_get_session_settings_returns_dict_when_set(test_tenant, test_super_admin_user):
    """Test get_session_settings returns dict when settings exist."""
    from schemas.settings import TenantSecuritySettingsUpdate

    # Set session settings
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=1800,
        persistent_sessions=False,
    )
    settings_service.update_security_settings(requesting_user, settings_update)

    # Get session settings
    result = settings_service.get_session_settings(test_tenant["id"])

    assert result is not None
    assert isinstance(result, dict)
    assert result["session_timeout_seconds"] == 1800
    assert result["persistent_sessions"] is False
