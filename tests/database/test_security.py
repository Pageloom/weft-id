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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])

    assert settings is not None
    assert settings["session_timeout_seconds"] == 3600
    assert settings["persistent_sessions"] is True
    assert settings["allow_users_edit_profile"] is True


def test_get_session_settings(test_tenant, test_admin_user):
    """Test retrieving session-related security settings."""
    import database

    # Create security settings
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=7200,
        persistent_sessions=False,
        allow_users_edit_profile=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.can_user_edit_profile(test_tenant["id"])

    assert result is not None
    assert result["allow_users_edit_profile"] is False


def test_update_security_settings(test_tenant, test_admin_user):
    """Test updating security settings (upsert behavior)."""
    import database

    # Initial insert
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=30,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])
    assert settings["session_timeout_seconds"] == 7200
    assert settings["persistent_sessions"] is False
    assert settings["allow_users_edit_profile"] is False


def test_update_security_settings_with_none_timeout(test_tenant, test_admin_user):
    """Test updating security settings with None timeout (no timeout)."""
    import database

    # Set timeout to None
    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=None,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=3,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=5,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=2,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=5,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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


# =============================================================================
# SAML domain-scoped user counts (database.saml.security)
# =============================================================================


def _create_saml_idp(tenant, user, name="Count IdP"):
    """Create a SAML IdP for domain count tests."""
    from uuid import uuid4

    import database

    return database.fetchone(
        tenant["id"],
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) VALUES (
            :tenant_id, :name, 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :created_by
        ) RETURNING id
        """,
        {
            "tenant_id": tenant["id"],
            "name": name,
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "created_by": user["id"],
        },
    )


def test_count_users_without_idp_in_domain_counts_password_users(test_tenant, test_user):
    """Test counting users in a domain who have no IdP assigned."""
    import database

    domain = test_user["email"].split("@")[1]

    count = database.saml.count_users_without_idp_in_domain(test_tenant["id"], domain)

    # test_user has a verified email, no IdP → should be counted
    assert count >= 1


def test_count_users_without_idp_in_domain_excludes_idp_users(
    test_tenant, test_user, test_admin_user
):
    """Test that users with an IdP assigned are not counted."""
    import database

    idp = _create_saml_idp(test_tenant, test_user)
    domain = test_user["email"].split("@")[1]

    # Assign test_user to IdP
    database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp["id"]))

    count = database.saml.count_users_without_idp_in_domain(test_tenant["id"], domain)

    # test_user now has an IdP - only admin should be counted
    admin_domain = test_admin_user["email"].split("@")[1]
    assert admin_domain == domain  # both use example.com

    # Only admin is without IdP
    assert count == 1


def test_count_users_without_idp_in_domain_excludes_unverified_emails(test_tenant, test_user):
    """Test that users with unverified emails are not counted."""
    import database

    # test_tenant only has test_user; unverifying makes count drop to 0
    domain = test_user["email"].split("@")[1]
    count_before = database.saml.count_users_without_idp_in_domain(test_tenant["id"], domain)
    assert count_before >= 1

    database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    count_after = database.saml.count_users_without_idp_in_domain(test_tenant["id"], domain)
    assert count_after == count_before - 1


def test_count_users_without_idp_in_domain_zero_for_unknown_domain(test_tenant):
    """Test that an unknown domain returns 0."""
    import database

    count = database.saml.count_users_without_idp_in_domain(
        test_tenant["id"], "unknowndomain.invalid"
    )

    assert count == 0


def test_count_users_with_idp_in_domain_counts_assigned_users(test_tenant, test_user):
    """Test counting users in a domain who are assigned to a specific IdP."""
    import database

    idp = _create_saml_idp(test_tenant, test_user)
    domain = test_user["email"].split("@")[1]

    # Before assignment: 0
    count_before = database.saml.count_users_with_idp_in_domain(
        test_tenant["id"], domain, str(idp["id"])
    )
    assert count_before == 0

    # Assign user
    database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp["id"]))

    count_after = database.saml.count_users_with_idp_in_domain(
        test_tenant["id"], domain, str(idp["id"])
    )
    assert count_after == 1


def test_count_users_with_idp_in_domain_scoped_to_specific_idp(
    test_tenant, test_user, test_admin_user
):
    """Test that count is scoped to the given IdP, not all IdPs."""
    import database

    idp_a = _create_saml_idp(test_tenant, test_user, name="Scope IdP A")
    idp_b = _create_saml_idp(test_tenant, test_user, name="Scope IdP B")
    domain = test_user["email"].split("@")[1]

    # Assign each user to a different IdP
    database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp_a["id"]))
    database.users.update_user_saml_idp(
        test_tenant["id"], str(test_admin_user["id"]), str(idp_b["id"])
    )

    count_a = database.saml.count_users_with_idp_in_domain(
        test_tenant["id"], domain, str(idp_a["id"])
    )
    count_b = database.saml.count_users_with_idp_in_domain(
        test_tenant["id"], domain, str(idp_b["id"])
    )

    assert count_a == 1
    assert count_b == 1


def test_count_users_with_idp_in_domain_zero_for_unknown_domain(test_tenant, test_user):
    """Test that an unknown domain returns 0 even when user has IdP."""
    import database

    idp = _create_saml_idp(test_tenant, test_user)
    database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp["id"]))

    count = database.saml.count_users_with_idp_in_domain(
        test_tenant["id"], "unknowndomain.invalid", str(idp["id"])
    )

    assert count == 0


# =============================================================================
# get_group_assertion_scope
# =============================================================================


def test_get_group_assertion_scope_default(test_tenant):
    """Test get_group_assertion_scope returns 'access_relevant' when no settings exist."""
    import database

    result = database.security.get_group_assertion_scope(test_tenant["id"])

    assert result == "access_relevant"


def test_get_group_assertion_scope_configured(test_tenant, test_admin_user):
    """Test get_group_assertion_scope returns configured value."""
    import database

    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=None,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="trunk",
        require_email_verification_for_login=False,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    result = database.security.get_group_assertion_scope(test_tenant["id"])

    assert result == "trunk"


def test_get_group_assertion_scope_all_values(test_tenant, test_admin_user):
    """Test get_group_assertion_scope returns each valid scope value."""
    import database

    for scope in ["all", "trunk", "access_relevant"]:
        database.security.update_security_settings(
            test_tenant["id"],
            timeout_seconds=None,
            persistent_sessions=True,
            allow_users_edit_profile=True,
            inactivity_threshold_days=None,
            max_certificate_lifetime_years=10,
            certificate_rotation_window_days=90,
            minimum_password_length=14,
            minimum_zxcvbn_score=3,
            group_assertion_scope=scope,
            require_email_verification_for_login=False,
            updated_by=test_admin_user["id"],
            tenant_id_value=test_tenant["id"],
        )

        result = database.security.get_group_assertion_scope(test_tenant["id"])
        assert result == scope


def test_get_security_settings_includes_group_assertion_scope(test_tenant, test_admin_user):
    """Test that get_security_settings returns group_assertion_scope field."""
    import database

    database.security.update_security_settings(
        test_tenant["id"],
        timeout_seconds=3600,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="all",
        require_email_verification_for_login=False,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    settings = database.security.get_security_settings(test_tenant["id"])

    assert settings is not None
    assert settings["group_assertion_scope"] == "all"
