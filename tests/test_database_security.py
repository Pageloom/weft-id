"""Tests for database.security module."""

import pytest


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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
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
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"]
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["session_timeout_seconds"] is None
