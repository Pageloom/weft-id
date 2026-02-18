"""Tests for database.security module."""


def test_get_security_settings(test_tenant, test_admin_user):
    """Test retrieving all security settings."""
    import database

    # First create some security settings
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=False,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])

    assert settings is not None
    assert settings["session_timeout_seconds"] == 3600
    assert settings["persistent_sessions"] is True
    assert settings["allow_users_edit_profile"] is True
    assert settings["allow_users_add_emails"] is False


def test_get_session_settings(test_tenant, test_admin_user):
    """Test retrieving session-related security settings."""
    import database

    # Create security settings
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=7200,
        persistent_sessions=False,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_session_settings(test_tenant["id"])

    assert settings is not None
    assert settings["session_timeout_seconds"] == 7200
    assert settings["persistent_sessions"] is False


def test_get_session_timeout(test_tenant, test_admin_user):
    """Test retrieving just the session timeout setting."""
    import database

    # Create security settings with specific timeout
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=1800,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_session_timeout(test_tenant["id"])

    assert settings is not None
    assert settings["session_timeout_seconds"] == 1800


def test_can_user_edit_profile(test_tenant, test_admin_user):
    """Test checking if users can edit their profile."""
    import database

    # Create settings where users CAN edit profile
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.can_user_edit_profile(test_tenant["id"])

    assert result is not None
    assert result["allow_users_edit_profile"] is True

    # Update to disallow profile editing
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=False,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.can_user_edit_profile(test_tenant["id"])

    assert result is not None
    assert result["allow_users_edit_profile"] is False


def test_can_user_add_emails(test_tenant, test_admin_user):
    """Test checking if users can add email addresses."""
    import database

    # Create settings where users CAN add emails
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.can_user_add_emails(test_tenant["id"])

    assert result is not None
    assert result["allow_users_add_emails"] is True

    # Update to disallow adding emails
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=False,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.can_user_add_emails(test_tenant["id"])

    assert result is not None
    assert result["allow_users_add_emails"] is False


def test_update_security_settings(test_tenant, test_admin_user):
    """Test updating security settings (upsert behavior)."""
    import database

    # Initial insert
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["session_timeout_seconds"] == 3600

    # Update (should upsert)
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=7200,
        persistent_sessions=False,
        allow_users_edit_profile=False,
        allow_users_add_emails=False,
        inactivity_threshold_days=30,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["session_timeout_seconds"] == 7200
    assert settings["persistent_sessions"] is False
    assert settings["allow_users_edit_profile"] is False
    assert settings["allow_users_add_emails"] is False


def test_update_security_settings_with_none_timeout(test_tenant, test_admin_user):
    """Test updating security settings with None timeout (no timeout)."""
    import database

    # Set timeout to None
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=None,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["session_timeout_seconds"] is None


def test_get_security_settings_includes_certificate_lifetime(test_tenant, test_admin_user):
    """Test that get_security_settings returns max_certificate_lifetime_years."""
    import database

    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=3,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])

    assert settings is not None
    assert settings["max_certificate_lifetime_years"] == 3


def test_get_certificate_lifetime_default(test_tenant):
    """Test get_certificate_lifetime returns 10 when no settings exist."""
    import database

    result = database.security.get_certificate_lifetime(test_tenant["id"])

    assert result == 10


def test_get_certificate_lifetime_configured(test_tenant, test_admin_user):
    """Test get_certificate_lifetime returns configured value."""
    import database

    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=None,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=5,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.get_certificate_lifetime(test_tenant["id"])

    assert result == 5


def test_update_security_settings_with_certificate_lifetime(test_tenant, test_admin_user):
    """Test updating security settings includes certificate lifetime."""
    import database

    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=2,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["max_certificate_lifetime_years"] == 2

    # Update to different value
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=5,
        certificate_rotation_window_days=90,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["max_certificate_lifetime_years"] == 5


# =============================================================================
# Note: get_all_tenants_with_inactivity_threshold() is tested via
# test_jobs_inactivate_idle_users.py with mocked database calls.
#
# Direct database testing is not possible because the function uses get_pool()
# directly (bypassing the session context manager), but RLS is still active.
# The RLS policy requires app.tenant_id to be set to a valid UUID, and when
# it's not set, the policy's cast of ''::uuid fails.
#
# This is by design - the function is meant for background workers that run
# with elevated privileges (BYPASSRLS) in production.
# =============================================================================
