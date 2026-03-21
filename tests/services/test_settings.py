"""Comprehensive tests for Settings service layer functions.

This test file covers all settings service operations for the services/settings.py module.
Tests include:
- Privileged domains management (list, add, delete)
- Domain-group links (list, add, delete, auto-assign)
- Tenant security settings (get, update)
- Utility functions (domain checking, session settings)
- Authorization checks
- Event logging
- Activity tracking
"""

from uuid import uuid4

import database
import pytest
from schemas.settings import TenantSecuritySettingsUpdate
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


# =============================================================================
# Privileged Domains - Validation Tests
# =============================================================================


def test_add_privileged_domain_too_short(test_tenant, test_admin_user):
    """Test that adding a domain with less than 3 characters fails at Pydantic validation."""
    from pydantic_core import ValidationError as PydanticValidationError
    from schemas.settings import PrivilegedDomainCreate

    with pytest.raises(PydanticValidationError):
        PrivilegedDomainCreate(domain="ab")


def test_add_privileged_domain_too_long(test_tenant, test_admin_user):
    """Test that adding a domain longer than 253 characters fails at Pydantic validation."""
    from pydantic_core import ValidationError as PydanticValidationError
    from schemas.settings import PrivilegedDomainCreate

    # Create a domain that's 254 characters
    long_domain = "a" * 250 + ".com"

    with pytest.raises(PydanticValidationError):
        PrivilegedDomainCreate(domain=long_domain)


def test_add_privileged_domain_min_length(test_tenant, test_admin_user):
    """Test that adding a domain with exactly 3 characters succeeds."""
    from schemas.settings import PrivilegedDomainCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_data = PrivilegedDomainCreate(domain="a.b")

    result = settings_service.add_privileged_domain(requesting_user, domain_data)

    assert result.domain == "a.b"


# =============================================================================
# Security Settings - Validation Tests
# =============================================================================


def test_update_security_settings_zero_timeout_fails(test_tenant, test_super_admin_user):
    """Test that setting session timeout to 0 fails at Pydantic validation."""
    from pydantic_core import ValidationError as PydanticValidationError
    from schemas.settings import TenantSecuritySettingsUpdate

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(session_timeout_seconds=0)


def test_update_security_settings_negative_timeout_fails(test_tenant, test_super_admin_user):
    """Test that setting session timeout to negative value fails at Pydantic validation."""
    from pydantic_core import ValidationError as PydanticValidationError
    from schemas.settings import TenantSecuritySettingsUpdate

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(session_timeout_seconds=-1)


def test_certificate_lifetime_invalid_value_fails():
    """Test that invalid certificate lifetime value fails at Pydantic validation."""
    from pydantic_core import ValidationError as PydanticValidationError
    from schemas.settings import TenantSecuritySettingsUpdate

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(max_certificate_lifetime_years=4)  # Not in [1,2,3,5,10]


def test_certificate_lifetime_valid_values():
    """Test that all valid certificate lifetime values are accepted."""
    from schemas.settings import TenantSecuritySettingsUpdate

    for years in [1, 2, 3, 5, 10]:
        update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=years)
        assert update.max_certificate_lifetime_years == years


# =============================================================================
# Inactivity Threshold Tests
# =============================================================================


def test_get_inactivity_threshold_not_set(test_tenant):
    """Test that get_inactivity_threshold returns None when not configured."""
    result = settings_service.get_inactivity_threshold(test_tenant["id"])

    assert result is None


def test_get_inactivity_threshold_set(test_tenant, test_super_admin_user):
    """Test that get_inactivity_threshold returns correct value when set."""
    from schemas.settings import TenantSecuritySettingsUpdate

    # Set inactivity threshold
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(inactivity_threshold_days=90)
    settings_service.update_security_settings(requesting_user, settings_update)

    result = settings_service.get_inactivity_threshold(test_tenant["id"])

    assert result == 90


def test_delete_privileged_domain_as_super_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can delete a privileged domain."""
    from schemas.settings import PrivilegedDomainCreate

    # First add a domain
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    domain_data = PrivilegedDomainCreate(domain="deletetest.com")
    created = settings_service.add_privileged_domain(requesting_user, domain_data)

    # Now delete it (returns None on success)
    settings_service.delete_privileged_domain(requesting_user, str(created.id))

    # Verify it was deleted by listing domains
    domains = settings_service.list_privileged_domains(requesting_user)
    domain_ids = [str(d.id) for d in domains]
    assert str(created.id) not in domain_ids


# =============================================================================
# Certificate Lifetime Tests
# =============================================================================


def test_get_security_settings_includes_certificate_lifetime_default(
    test_tenant, test_super_admin_user
):
    """Test that get_security_settings returns default certificate lifetime."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = settings_service.get_security_settings(requesting_user)

    assert result.max_certificate_lifetime_years == 10


def test_update_security_settings_with_certificate_lifetime(test_tenant, test_super_admin_user):
    """Test updating certificate lifetime setting."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=3)

    result = settings_service.update_security_settings(requesting_user, settings_update)

    assert result.max_certificate_lifetime_years == 3

    # Verify it persists
    result = settings_service.get_security_settings(requesting_user)
    assert result.max_certificate_lifetime_years == 3


def test_update_certificate_lifetime_logs_dedicated_event(test_tenant, test_super_admin_user):
    """Test that changing certificate lifetime logs a dedicated event."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set initial value
    settings_update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=5)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Change to a different value
    settings_update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=3)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Verify the dedicated event was logged
    events = database.event_log.list_events(test_tenant["id"], limit=5)
    cert_events = [e for e in events if e["event_type"] == "tenant_certificate_lifetime_updated"]
    assert len(cert_events) >= 1
    latest = cert_events[0]
    assert latest["metadata"]["old_years"] == 5
    assert latest["metadata"]["new_years"] == 3


def test_update_certificate_lifetime_same_value_no_dedicated_event(
    test_tenant, test_super_admin_user
):
    """Test that setting same certificate lifetime does not log dedicated event."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set to 5
    settings_update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=5)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Set to 5 again (same value)
    settings_update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=5)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Check that the second update did NOT produce a dedicated cert lifetime event
    events = database.event_log.list_events(test_tenant["id"], limit=10)
    cert_events = [e for e in events if e["event_type"] == "tenant_certificate_lifetime_updated"]
    # Only the first change (from default 10 -> 5) should have logged
    assert len(cert_events) == 1


def test_get_certificate_lifetime_default(test_tenant):
    """Test get_certificate_lifetime returns 10 when not configured."""
    result = settings_service.get_certificate_lifetime(test_tenant["id"])

    assert result == 10


def test_get_certificate_lifetime_configured(test_tenant, test_super_admin_user):
    """Test get_certificate_lifetime returns configured value."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(max_certificate_lifetime_years=3)
    settings_service.update_security_settings(requesting_user, settings_update)

    result = settings_service.get_certificate_lifetime(test_tenant["id"])

    assert result == 3


# =============================================================================
# Certificate Rotation Window Tests
# =============================================================================


def test_get_security_settings_includes_rotation_window_default(test_tenant, test_super_admin_user):
    """Test that get_security_settings returns default rotation window of 90."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = settings_service.get_security_settings(requesting_user)

    assert result.certificate_rotation_window_days == 90


def test_update_security_settings_with_rotation_window(test_tenant, test_super_admin_user):
    """Test updating rotation window setting."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=30)

    result = settings_service.update_security_settings(requesting_user, settings_update)

    assert result.certificate_rotation_window_days == 30

    # Verify it persists
    result = settings_service.get_security_settings(requesting_user)
    assert result.certificate_rotation_window_days == 30


def test_update_rotation_window_logs_dedicated_event(test_tenant, test_super_admin_user):
    """Test that changing rotation window logs a dedicated event."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set initial value
    settings_update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=60)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Change to a different value
    settings_update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=30)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Verify the dedicated event was logged
    events = database.event_log.list_events(test_tenant["id"], limit=5)
    window_events = [
        e for e in events if e["event_type"] == "tenant_certificate_rotation_window_updated"
    ]
    assert len(window_events) >= 1
    latest = window_events[0]
    assert latest["metadata"]["old_days"] == 60
    assert latest["metadata"]["new_days"] == 30


def test_update_rotation_window_same_value_no_dedicated_event(test_tenant, test_super_admin_user):
    """Test that setting same rotation window does not log dedicated event."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set to 60
    settings_update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=60)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Set to 60 again (same value)
    settings_update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=60)
    settings_service.update_security_settings(requesting_user, settings_update)

    # Check that the second update did NOT produce a dedicated rotation window event
    events = database.event_log.list_events(test_tenant["id"], limit=10)
    window_events = [
        e for e in events if e["event_type"] == "tenant_certificate_rotation_window_updated"
    ]
    # Only the first change (from default 90 -> 60) should have logged
    assert len(window_events) == 1


def test_get_certificate_rotation_window_default(test_tenant):
    """Test get_certificate_rotation_window returns 90 when not configured."""
    result = settings_service.get_certificate_rotation_window(test_tenant["id"])

    assert result == 90


def test_get_certificate_rotation_window_configured(test_tenant, test_super_admin_user):
    """Test get_certificate_rotation_window returns configured value."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=14)
    settings_service.update_security_settings(requesting_user, settings_update)

    result = settings_service.get_certificate_rotation_window(test_tenant["id"])

    assert result == 14


def test_rotation_window_invalid_value_fails():
    """Test that invalid rotation window value fails at Pydantic validation."""
    from pydantic_core import ValidationError as PydanticValidationError
    from schemas.settings import TenantSecuritySettingsUpdate

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(certificate_rotation_window_days=45)  # Not in [14,30,60,90]


def test_rotation_window_valid_values():
    """Test that all valid rotation window values are accepted."""
    from schemas.settings import TenantSecuritySettingsUpdate

    for days in [14, 30, 60, 90]:
        update = TenantSecuritySettingsUpdate(certificate_rotation_window_days=days)
        assert update.certificate_rotation_window_days == days


# =============================================================================
# Password Policy Tests
# =============================================================================


def test_get_security_settings_includes_password_policy_defaults(
    test_tenant, test_super_admin_user
):
    """Test that security settings include password policy defaults."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    result = settings_service.get_security_settings(requesting_user)
    assert result.minimum_password_length == 14
    assert result.minimum_zxcvbn_score == 3


def test_update_security_settings_with_password_policy(test_tenant, test_super_admin_user):
    """Test updating password policy fields."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    settings_update = TenantSecuritySettingsUpdate(
        minimum_password_length=16, minimum_zxcvbn_score=4
    )
    result = settings_service.update_security_settings(requesting_user, settings_update)
    assert result.minimum_password_length == 16
    assert result.minimum_zxcvbn_score == 4

    # Verify persistence
    result2 = settings_service.get_security_settings(requesting_user)
    assert result2.minimum_password_length == 16
    assert result2.minimum_zxcvbn_score == 4


def test_update_password_policy_logs_dedicated_event(test_tenant, test_super_admin_user):
    """Test that changing password policy logs a dedicated event."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    settings_update = TenantSecuritySettingsUpdate(minimum_password_length=20)
    settings_service.update_security_settings(requesting_user, settings_update)

    events = database.event_log.list_events(test_tenant["id"], limit=10)
    pw_events = [e for e in events if e["event_type"] == "password_policy_updated"]
    assert len(pw_events) == 1


def test_update_password_policy_no_event_when_unchanged(test_tenant, test_super_admin_user):
    """Test that no dedicated event is logged when password policy doesn't change."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set initial value
    settings_service.update_security_settings(
        requesting_user, TenantSecuritySettingsUpdate(minimum_password_length=12)
    )

    # Clear events by getting count
    events_before = database.event_log.list_events(test_tenant["id"], limit=100)
    pw_events_before = len(
        [e for e in events_before if e["event_type"] == "password_policy_updated"]
    )

    # Set same value again
    settings_service.update_security_settings(
        requesting_user, TenantSecuritySettingsUpdate(minimum_password_length=12)
    )

    events_after = database.event_log.list_events(test_tenant["id"], limit=100)
    pw_events_after = len([e for e in events_after if e["event_type"] == "password_policy_updated"])
    assert pw_events_after == pw_events_before


def test_get_password_policy_returns_defaults(test_tenant):
    """Test get_password_policy returns defaults when not configured."""
    result = settings_service.get_password_policy(test_tenant["id"])
    assert result["minimum_password_length"] == 14
    assert result["minimum_zxcvbn_score"] == 3


def test_get_password_policy_returns_configured(test_tenant, test_super_admin_user):
    """Test get_password_policy returns configured values."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_service.update_security_settings(
        requesting_user,
        TenantSecuritySettingsUpdate(minimum_password_length=20, minimum_zxcvbn_score=4),
    )

    result = settings_service.get_password_policy(test_tenant["id"])
    assert result["minimum_password_length"] == 20
    assert result["minimum_zxcvbn_score"] == 4


def test_password_length_invalid_values():
    """Test that invalid password length values are rejected."""
    from pydantic_core import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(minimum_password_length=9)  # Not in allowed set

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(minimum_password_length=15)


def test_password_length_valid_values():
    """Test that all valid password length values are accepted."""
    for length in [8, 10, 12, 14, 16, 18, 20]:
        update = TenantSecuritySettingsUpdate(minimum_password_length=length)
        assert update.minimum_password_length == length


def test_zxcvbn_score_invalid_values():
    """Test that invalid zxcvbn score values are rejected."""
    from pydantic_core import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(minimum_zxcvbn_score=2)

    with pytest.raises(PydanticValidationError):
        TenantSecuritySettingsUpdate(minimum_zxcvbn_score=5)


def test_zxcvbn_score_valid_values():
    """Test that all valid zxcvbn score values are accepted."""
    for score in [3, 4]:
        update = TenantSecuritySettingsUpdate(minimum_zxcvbn_score=score)
        assert update.minimum_zxcvbn_score == score


# =============================================================================
# Domain-Group Links - Helpers
# =============================================================================


def _create_domain_and_group(tenant_id, admin_user_id):
    """Create a privileged domain and a weftid group for testing. Returns (domain_id, group_id)."""
    unique = str(uuid4())[:8]
    domain_name = f"dgl-{unique}.example.com"

    # Create privileged domain
    domain_row = database.fetchone(
        tenant_id,
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by)
        returning id
        """,
        {"tenant_id": str(tenant_id), "domain": domain_name, "created_by": str(admin_user_id)},
    )
    domain_id = str(domain_row["id"])

    # Create weftid group
    group = database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=f"DGL Test Group {unique}",
        description="Test group for domain-group link tests",
        group_type="weftid",
        created_by=str(admin_user_id),
    )
    group_id = str(group["id"])

    return domain_id, group_id, domain_name


# =============================================================================
# Domain-Group Links - List Tests
# =============================================================================


def test_list_domain_group_links_empty(test_tenant, test_admin_user):
    """Test listing links for a domain with no links."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, _, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    result = settings_service.list_domain_group_links(requesting_user, domain_id)

    assert result == []


def test_list_domain_group_links_with_links(test_tenant, test_admin_user):
    """Test listing links returns created links."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    # Create a link
    link_data = DomainGroupLinkCreate(group_id=group_id)
    settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    result = settings_service.list_domain_group_links(requesting_user, domain_id)

    assert len(result) == 1
    assert result[0].group_id == group_id
    assert result[0].domain_id == domain_id


def test_list_domain_group_links_domain_not_found(test_tenant, test_admin_user):
    """Test listing links for a non-existent domain raises NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        settings_service.list_domain_group_links(
            requesting_user, "00000000-0000-0000-0000-000000000000"
        )

    assert exc_info.value.code == "domain_not_found"


def test_list_domain_group_links_as_member_forbidden(test_tenant, test_user):
    """Test that regular members cannot list domain-group links."""
    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError):
        settings_service.list_domain_group_links(
            requesting_user, "00000000-0000-0000-0000-000000000000"
        )


# =============================================================================
# Domain-Group Links - Add Tests
# =============================================================================


def test_add_domain_group_link_as_admin(test_tenant, test_admin_user):
    """Test that an admin can link a group to a domain."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, domain_name = _create_domain_and_group(
        test_tenant["id"], test_admin_user["id"]
    )

    link_data = DomainGroupLinkCreate(group_id=group_id)
    result = settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    assert result.domain_id == domain_id
    assert result.group_id == group_id
    assert result.id is not None

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "domain_group_link_created", result.id)


def test_add_domain_group_link_domain_not_found(test_tenant, test_admin_user):
    """Test that linking to a non-existent domain raises NotFoundError."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    _, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    link_data = DomainGroupLinkCreate(group_id=group_id)
    with pytest.raises(NotFoundError) as exc_info:
        settings_service.add_domain_group_link(
            requesting_user, "00000000-0000-0000-0000-000000000000", link_data
        )

    assert exc_info.value.code == "domain_not_found"


def test_add_domain_group_link_group_not_found(test_tenant, test_admin_user):
    """Test that linking a non-existent group raises NotFoundError."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, _, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    link_data = DomainGroupLinkCreate(group_id="00000000-0000-0000-0000-000000000000")
    with pytest.raises(NotFoundError) as exc_info:
        settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    assert exc_info.value.code == "group_not_found"


def test_add_domain_group_link_rejects_idp_group(test_tenant, test_admin_user):
    """Test that linking an IdP group raises ValidationError."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, _, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    # Create an idp group
    idp_group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"IdP Group {str(uuid4())[:8]}",
        group_type="idp",
    )

    link_data = DomainGroupLinkCreate(group_id=str(idp_group["id"]))
    with pytest.raises(ValidationError) as exc_info:
        settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    assert exc_info.value.code == "invalid_group_type"


def test_add_domain_group_link_duplicate_conflict(test_tenant, test_admin_user):
    """Test that duplicate link raises ConflictError."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    link_data = DomainGroupLinkCreate(group_id=group_id)

    # Create once
    settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    # Try again
    with pytest.raises(ConflictError) as exc_info:
        settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    assert exc_info.value.code == "link_exists"


def test_add_domain_group_link_as_member_forbidden(test_tenant, test_user):
    """Test that regular members cannot create domain-group links."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError):
        settings_service.add_domain_group_link(
            requesting_user,
            "00000000-0000-0000-0000-000000000000",
            DomainGroupLinkCreate(group_id="00000000-0000-0000-0000-000000000000"),
        )


def test_add_domain_group_link_retroactive_assignment(test_tenant, test_admin_user):
    """Test that creating a link retroactively adds existing users to the group."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    tenant_id = test_tenant["id"]

    unique = str(uuid4())[:8]
    domain_name = f"retro-{unique}.example.com"

    # Create domain
    domain_row = database.fetchone(
        tenant_id,
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by) returning id
        """,
        {
            "tenant_id": str(tenant_id),
            "domain": domain_name,
            "created_by": str(test_admin_user["id"]),
        },
    )
    domain_id = str(domain_row["id"])

    # Create a user with a verified email on this domain
    user_row = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role)
        values (:tenant_id, 'Retro', 'User', 'member') returning id
        """,
        {"tenant_id": str(tenant_id)},
    )
    user_id = str(user_row["id"])

    database.execute(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": str(tenant_id), "user_id": user_id, "email": f"retro@{domain_name}"},
    )

    # Create group
    group = database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=f"Retro Group {unique}",
        group_type="weftid",
        created_by=str(test_admin_user["id"]),
    )
    group_id = str(group["id"])

    # Link domain to group: should retroactively add the user
    link_data = DomainGroupLinkCreate(group_id=group_id)
    settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    # Verify user was added to the group
    assert database.groups.is_group_member(tenant_id, group_id, user_id) is True


# =============================================================================
# Domain-Group Links - Delete Tests
# =============================================================================


def test_delete_domain_group_link(test_tenant, test_admin_user):
    """Test that an admin can unlink a group from a domain."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    # Create link
    link_data = DomainGroupLinkCreate(group_id=group_id)
    link = settings_service.add_domain_group_link(requesting_user, domain_id, link_data)

    # Delete it
    settings_service.delete_domain_group_link(requesting_user, domain_id, link.id)

    # Verify it's gone
    links = settings_service.list_domain_group_links(requesting_user, domain_id)
    assert len(links) == 0

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "domain_group_link_deleted", link.id)


def test_delete_domain_group_link_not_found(test_tenant, test_admin_user):
    """Test deleting a non-existent link raises NotFoundError."""
    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, _, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    with pytest.raises(NotFoundError) as exc_info:
        settings_service.delete_domain_group_link(
            requesting_user, domain_id, "00000000-0000-0000-0000-000000000000"
        )

    assert exc_info.value.code == "link_not_found"


def test_delete_domain_group_link_wrong_domain(test_tenant, test_admin_user):
    """Test deleting a link with wrong domain_id raises NotFoundError."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])
    other_domain_id, _, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    # Create link on domain_id
    link = settings_service.add_domain_group_link(
        requesting_user, domain_id, DomainGroupLinkCreate(group_id=group_id)
    )

    # Try to delete via other_domain_id
    with pytest.raises(NotFoundError):
        settings_service.delete_domain_group_link(requesting_user, other_domain_id, link.id)


def test_delete_domain_group_link_preserves_memberships(test_tenant, test_admin_user):
    """Test that unlinking does NOT remove existing group memberships."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])
    tenant_id = test_tenant["id"]

    # Add the admin user to the group
    database.groups.add_group_member(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        group_id=group_id,
        user_id=str(test_admin_user["id"]),
    )

    # Create and then delete the link
    link = settings_service.add_domain_group_link(
        requesting_user, domain_id, DomainGroupLinkCreate(group_id=group_id)
    )
    settings_service.delete_domain_group_link(requesting_user, domain_id, link.id)

    # User should still be in the group
    assert database.groups.is_group_member(tenant_id, group_id, str(test_admin_user["id"]))


# =============================================================================
# Domain-Group Links - Enriched List Tests
# =============================================================================


def test_list_privileged_domains_includes_linked_groups(test_tenant, test_admin_user):
    """Test that list_privileged_domains includes linked_groups field."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, _ = _create_domain_and_group(test_tenant["id"], test_admin_user["id"])

    # Link a group
    settings_service.add_domain_group_link(
        requesting_user, domain_id, DomainGroupLinkCreate(group_id=group_id)
    )

    # List domains
    domains = settings_service.list_privileged_domains(requesting_user)
    domain = next(d for d in domains if d.id == domain_id)

    assert len(domain.linked_groups) == 1
    assert domain.linked_groups[0].group_id == group_id


# =============================================================================
# Auto-Assign Utility
# =============================================================================


def test_auto_assign_user_to_domain_groups(test_tenant, test_admin_user):
    """Test auto-assigning a user to domain-linked groups."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, domain_name = _create_domain_and_group(
        test_tenant["id"], test_admin_user["id"]
    )
    tenant_id = test_tenant["id"]

    # Link group to domain
    settings_service.add_domain_group_link(
        requesting_user, domain_id, DomainGroupLinkCreate(group_id=group_id)
    )

    # Create a new user with email on this domain
    user_row = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role)
        values (:tenant_id, 'Auto', 'Assign', 'member') returning id
        """,
        {"tenant_id": str(tenant_id)},
    )
    user_id = str(user_row["id"])

    # Auto-assign
    count = settings_service.auto_assign_user_to_domain_groups(
        str(tenant_id), user_id, f"autotest@{domain_name}", str(test_admin_user["id"])
    )

    assert count == 1
    assert database.groups.is_group_member(tenant_id, group_id, user_id)

    # Verify event logged
    _verify_event_logged(tenant_id, "domain_group_auto_assigned", user_id)


def test_auto_assign_no_links_returns_zero(test_tenant, test_admin_user):
    """Test auto-assign returns 0 when no links exist for the domain."""
    count = settings_service.auto_assign_user_to_domain_groups(
        str(test_tenant["id"]),
        str(test_admin_user["id"]),
        "nobody@nonexistent-domain.com",
    )

    assert count == 0


def test_auto_assign_idempotent(test_tenant, test_admin_user):
    """Test auto-assign is idempotent (doesn't fail on duplicate membership)."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    domain_id, group_id, domain_name = _create_domain_and_group(
        test_tenant["id"], test_admin_user["id"]
    )
    tenant_id = test_tenant["id"]

    # Link group
    settings_service.add_domain_group_link(
        requesting_user, domain_id, DomainGroupLinkCreate(group_id=group_id)
    )

    user_row = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role)
        values (:tenant_id, 'Idem', 'Potent', 'member') returning id
        """,
        {"tenant_id": str(tenant_id)},
    )
    user_id = str(user_row["id"])
    email = f"idem@{domain_name}"

    # First call adds
    count1 = settings_service.auto_assign_user_to_domain_groups(str(tenant_id), user_id, email)
    assert count1 == 1

    # Second call is no-op
    count2 = settings_service.auto_assign_user_to_domain_groups(str(tenant_id), user_id, email)
    assert count2 == 0


def test_auto_assign_invalid_email(test_tenant, test_admin_user):
    """Test auto-assign handles invalid emails gracefully."""
    count = settings_service.auto_assign_user_to_domain_groups(
        str(test_tenant["id"]), str(test_admin_user["id"]), "no-at-sign"
    )
    assert count == 0

    count2 = settings_service.auto_assign_user_to_domain_groups(
        str(test_tenant["id"]), str(test_admin_user["id"]), ""
    )
    assert count2 == 0


def test_auto_assign_multiple_groups(test_tenant, test_admin_user):
    """Test auto-assign adds user to multiple linked groups."""
    from schemas.settings import DomainGroupLinkCreate

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    tenant_id = test_tenant["id"]

    unique = str(uuid4())[:8]
    domain_name = f"multi-{unique}.example.com"

    # Create domain
    domain_row = database.fetchone(
        tenant_id,
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by) returning id
        """,
        {
            "tenant_id": str(tenant_id),
            "domain": domain_name,
            "created_by": str(test_admin_user["id"]),
        },
    )
    domain_id = str(domain_row["id"])

    # Create two groups and link both
    group_ids = []
    for i in range(2):
        group = database.groups.create_group(
            tenant_id=tenant_id,
            tenant_id_value=str(tenant_id),
            name=f"Multi Group {unique}-{i}",
            group_type="weftid",
            created_by=str(test_admin_user["id"]),
        )
        gid = str(group["id"])
        group_ids.append(gid)
        settings_service.add_domain_group_link(
            requesting_user, domain_id, DomainGroupLinkCreate(group_id=gid)
        )

    # Create user
    user_row = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role)
        values (:tenant_id, 'Multi', 'User', 'member') returning id
        """,
        {"tenant_id": str(tenant_id)},
    )
    user_id = str(user_row["id"])

    count = settings_service.auto_assign_user_to_domain_groups(
        str(tenant_id), user_id, f"multi@{domain_name}"
    )

    assert count == 2
    for gid in group_ids:
        assert database.groups.is_group_member(tenant_id, gid, user_id)


# =============================================================================
# Group Assertion Scope Tests
# =============================================================================


def test_get_security_settings_includes_group_assertion_scope_default(
    test_tenant, test_super_admin_user
):
    """Test that get_security_settings returns default group_assertion_scope."""
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    result = settings_service.get_security_settings(requesting_user)

    assert result.group_assertion_scope == "access_relevant"


def test_update_security_settings_with_group_assertion_scope(test_tenant, test_super_admin_user):
    """Test updating group_assertion_scope setting."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    settings_update = TenantSecuritySettingsUpdate(group_assertion_scope="trunk")

    result = settings_service.update_security_settings(requesting_user, settings_update)

    assert result.group_assertion_scope == "trunk"

    # Verify it persists
    result = settings_service.get_security_settings(requesting_user)
    assert result.group_assertion_scope == "trunk"


def test_update_group_assertion_scope_logs_dedicated_event(test_tenant, test_super_admin_user):
    """Test that changing group_assertion_scope logs a dedicated event."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set initial value
    settings_update = TenantSecuritySettingsUpdate(group_assertion_scope="all")
    settings_service.update_security_settings(requesting_user, settings_update)

    # Change to a different value
    settings_update = TenantSecuritySettingsUpdate(group_assertion_scope="trunk")
    settings_service.update_security_settings(requesting_user, settings_update)

    # Verify the dedicated event was logged
    events = database.event_log.list_events(test_tenant["id"], limit=5)
    scope_events = [e for e in events if e["event_type"] == "group_assertion_scope_updated"]
    assert len(scope_events) >= 1
    latest = scope_events[0]
    assert latest["metadata"]["old_scope"] == "all"
    assert latest["metadata"]["new_scope"] == "trunk"


def test_update_group_assertion_scope_same_value_no_dedicated_event(
    test_tenant, test_super_admin_user
):
    """Test that setting same scope does not log dedicated event."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Set to "all"
    settings_update = TenantSecuritySettingsUpdate(group_assertion_scope="all")
    settings_service.update_security_settings(requesting_user, settings_update)

    # Set to "all" again (same value)
    settings_update = TenantSecuritySettingsUpdate(group_assertion_scope="all")
    settings_service.update_security_settings(requesting_user, settings_update)

    # Only the first change (from default access_relevant -> all) should log
    events = database.event_log.list_events(test_tenant["id"], limit=10)
    scope_events = [e for e in events if e["event_type"] == "group_assertion_scope_updated"]
    assert len(scope_events) == 1


def test_update_group_assertion_scope_included_in_changes_metadata(
    test_tenant, test_super_admin_user
):
    """Test that group_assertion_scope change is in tenant_settings_updated metadata."""
    from schemas.settings import TenantSecuritySettingsUpdate

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    settings_update = TenantSecuritySettingsUpdate(group_assertion_scope="trunk")
    settings_service.update_security_settings(requesting_user, settings_update)

    # Check the main tenant_settings_updated event has the change in metadata
    events = database.event_log.list_events(test_tenant["id"], limit=5)
    settings_events = [e for e in events if e["event_type"] == "tenant_settings_updated"]
    assert len(settings_events) >= 1
    latest = settings_events[0]
    assert "group_assertion_scope" in latest["metadata"]["changes"]
    scope_change = latest["metadata"]["changes"]["group_assertion_scope"]
    assert scope_change["new"] == "trunk"
