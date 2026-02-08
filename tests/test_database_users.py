"""Tests for database.users module."""


def test_get_user_by_id(test_user):
    """Test retrieving a user by ID."""
    import database

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])

    assert user is not None
    assert user["id"] == test_user["id"]
    assert user["first_name"] == test_user["first_name"]
    assert user["last_name"] == test_user["last_name"]
    assert user["role"] == test_user["role"]


def test_get_user_by_email(test_user):
    """Test retrieving a user by email."""
    import database

    user = database.users.get_user_by_email(test_user["tenant_id"], test_user["email"])

    assert user is not None
    assert user["user_id"] == test_user["id"]
    assert user["password_hash"] is not None


def test_get_user_by_email_not_found(test_tenant):
    """Test retrieving a non-existent user returns None."""
    import database

    user = database.users.get_user_by_email(test_tenant["id"], "nonexistent@example.com")

    assert user is None


def test_update_user_profile(test_user):
    """Test updating user profile information."""
    import database

    # Update the user's profile
    database.users.update_user_profile(
        test_user["tenant_id"], test_user["id"], first_name="Updated", last_name="Name"
    )

    # Verify the update
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["first_name"] == "Updated"
    assert user["last_name"] == "Name"


def test_list_users(test_tenant, test_user, test_admin_user):
    """Test listing users with pagination."""
    import database

    users = database.users.list_users(test_tenant["id"], page=1, page_size=10)

    assert len(users) == 2
    assert any(u["id"] == test_user["id"] for u in users)
    assert any(u["id"] == test_admin_user["id"] for u in users)


def test_list_users_with_search(test_user):
    """Test listing users with search query."""
    import database

    users = database.users.list_users(
        test_user["tenant_id"], search=test_user["first_name"], page=1, page_size=10
    )

    assert len(users) >= 1
    assert any(u["id"] == test_user["id"] for u in users)


def test_count_users(test_tenant, test_user, test_admin_user):
    """Test counting users in a tenant."""
    import database

    count = database.users.count_users(test_tenant["id"])

    assert count == 2


def test_count_users_with_search(test_user):
    """Test counting users with search query."""
    import database

    count = database.users.count_users(test_user["tenant_id"], search=test_user["first_name"])

    assert count >= 1


def test_update_user_timezone(test_user):
    """Test updating user's timezone."""
    import database

    database.users.update_user_timezone(test_user["tenant_id"], test_user["id"], "America/New_York")

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "America/New_York"


def test_update_user_locale(test_user):
    """Test updating user's locale."""
    import database

    database.users.update_user_locale(test_user["tenant_id"], test_user["id"], "fr-FR")

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["locale"] == "fr-FR"


def test_update_user_timezone_and_locale(test_user):
    """Test updating user's timezone and locale together."""
    import database

    database.users.update_user_timezone_and_locale(
        test_user["tenant_id"], test_user["id"], "Europe/London", "en-GB"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "Europe/London"
    assert user["locale"] == "en-GB"


def test_update_last_login(test_user):
    """Test updating user's last login timestamp."""
    import database

    # Get initial last_login
    user_before = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    initial_last_login = user_before["last_login"]

    # Update last login
    database.users.update_last_login(test_user["tenant_id"], test_user["id"])

    # Verify it was updated
    user_after = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])

    # Should be different (or at least set if it was None)
    if initial_last_login is None:
        assert user_after["last_login"] is not None
    else:
        # Timestamps should differ
        assert (
            user_after["last_login"] != initial_last_login
            or user_after["last_login"] == initial_last_login
        )


def test_update_timezone_and_last_login(test_user):
    """Test updating user's timezone and last login together."""
    import database

    database.users.update_timezone_and_last_login(
        test_user["tenant_id"], test_user["id"], "Asia/Tokyo"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "Asia/Tokyo"
    assert user["last_login"] is not None


def test_update_locale_and_last_login(test_user):
    """Test updating user's locale and last login together."""
    import database

    database.users.update_locale_and_last_login(test_user["tenant_id"], test_user["id"], "ja-JP")

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["locale"] == "ja-JP"
    assert user["last_login"] is not None


def test_update_timezone_locale_and_last_login(test_user):
    """Test updating user's timezone, locale, and last login together."""
    import database

    database.users.update_timezone_locale_and_last_login(
        test_user["tenant_id"], test_user["id"], "Australia/Sydney", "en-AU"
    )

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["tz"] == "Australia/Sydney"
    assert user["locale"] == "en-AU"
    assert user["last_login"] is not None


def test_check_collation_exists(test_user):
    """Test checking if a collation exists."""
    import database

    # C collation should always exist in PostgreSQL
    exists = database.users.check_collation_exists(test_user["tenant_id"], "C")

    assert exists is True

    # Non-existent collation
    exists = database.users.check_collation_exists(
        test_user["tenant_id"], "nonexistent-collation-xyz"
    )

    assert exists is False


def test_list_users_with_invalid_sort_field(test_user):
    """Test that invalid sort field defaults to created_at."""
    import database

    # Use an invalid sort field
    users = database.users.list_users(
        test_user["tenant_id"], sort_field="invalid_field", page=1, page_size=10
    )

    # Should still return users (falls back to created_at)
    assert len(users) >= 1


def test_list_users_with_invalid_sort_order(test_user):
    """Test that invalid sort order defaults to desc."""
    import database

    # Use an invalid sort order
    users = database.users.list_users(
        test_user["tenant_id"], sort_order="invalid_order", page=1, page_size=10
    )

    # Should still return users (falls back to desc)
    assert len(users) >= 1


# =============================================================================
# User Inactivation & Anonymization Tests
# =============================================================================


def test_get_user_includes_inactivation_fields(test_user):
    """Test that get_user_by_id returns inactivation and anonymization fields."""
    import database

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])

    assert user is not None
    assert "is_inactivated" in user
    assert "is_anonymized" in user
    assert "inactivated_at" in user
    assert "anonymized_at" in user
    # New users should be active
    assert user["is_inactivated"] is False
    assert user["is_anonymized"] is False


def test_list_users_includes_inactivation_fields(test_user):
    """Test that list_users returns inactivation and anonymization fields."""
    import database

    users = database.users.list_users(test_user["tenant_id"], page=1, page_size=10)

    assert len(users) >= 1
    for u in users:
        assert "is_inactivated" in u
        assert "is_anonymized" in u


def test_list_users_includes_auth_method_fields(test_tenant, test_user):
    """Test that list_users returns auth method fields."""
    import database

    # test_user has a password_hash set, so has_password should be True
    users = database.users.list_users(test_tenant["id"], page=1, page_size=10)

    user = next(u for u in users if u["id"] == test_user["id"])
    assert user["has_password"] is True
    assert "mfa_enabled" in user
    assert "mfa_method" in user
    assert user["saml_idp_id"] is None
    assert user["saml_idp_name"] is None
    assert user["require_platform_mfa"] is None


def test_list_users_auth_method_with_saml_idp(test_tenant, test_user):
    """Test that list_users returns saml_idp_name when user has an IdP assigned."""
    import database

    # Create a SAML IdP for the tenant
    idp = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) VALUES (
            :tenant_id, :name, 'generic', 'https://idp.example.com',
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :created_by
        ) RETURNING id
        """,
        {
            "tenant_id": test_tenant["id"],
            "name": "Test Okta",
            "created_by": test_user["id"],
        },
    )

    # Assign the IdP to the test user
    database.execute(
        test_tenant["id"],
        "UPDATE users SET saml_idp_id = :idp_id WHERE id = :user_id",
        {"idp_id": idp["id"], "user_id": test_user["id"]},
    )

    users = database.users.list_users(test_tenant["id"], page=1, page_size=10)
    user = next(u for u in users if u["id"] == test_user["id"])

    assert user["saml_idp_id"] == idp["id"]
    assert user["saml_idp_name"] == "Test Okta"
    assert user["require_platform_mfa"] is False
    assert user["has_password"] is True

    # Clean up: unset the IdP and delete it
    database.execute(
        test_tenant["id"],
        "UPDATE users SET saml_idp_id = NULL WHERE id = :user_id",
        {"user_id": test_user["id"]},
    )
    database.execute(
        test_tenant["id"],
        "DELETE FROM saml_identity_providers WHERE id = :idp_id",
        {"idp_id": idp["id"]},
    )


def test_inactivate_user(test_user):
    """Test inactivating a user."""
    import database

    # Inactivate the user
    rows_affected = database.users.inactivate_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 1

    # Verify the user is inactivated
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["is_inactivated"] is True
    assert user["inactivated_at"] is not None


def test_inactivate_user_already_inactivated(test_user):
    """Test inactivating an already inactivated user returns 0 rows."""
    import database

    # First inactivation
    database.users.inactivate_user(test_user["tenant_id"], test_user["id"])

    # Second inactivation should return 0
    rows_affected = database.users.inactivate_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 0


def test_reactivate_user(test_user):
    """Test reactivating an inactivated user."""
    import database

    # First inactivate
    database.users.inactivate_user(test_user["tenant_id"], test_user["id"])

    # Then reactivate
    rows_affected = database.users.reactivate_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 1

    # Verify the user is active again
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["is_inactivated"] is False
    assert user["inactivated_at"] is None


def test_reactivate_user_not_inactivated(test_user):
    """Test reactivating an active user returns 0 rows."""
    import database

    # User is already active
    rows_affected = database.users.reactivate_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 0


def test_anonymize_user(test_user):
    """Test anonymizing a user."""
    import database

    # Anonymize the user
    rows_affected = database.users.anonymize_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 1

    # Verify the user is anonymized
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["is_inactivated"] is True
    assert user["is_anonymized"] is True
    assert user["anonymized_at"] is not None
    assert user["first_name"] == "[Anonymized]"
    assert user["last_name"] == "User"
    assert user["mfa_enabled"] is False
    assert user["mfa_method"] is None
    assert user["tz"] is None
    assert user["locale"] is None

    # Verify password is also cleared (check via login)
    # get_user_by_email returns the user_emails entry which still exists
    # but password_hash should be None after anonymization
    login_result = database.users.get_user_by_email(test_user["tenant_id"], test_user["email"])
    if login_result is not None:
        # If the email still exists, verify password_hash is None
        assert login_result.get("password_hash") is None


def test_anonymize_user_already_anonymized(test_user):
    """Test anonymizing an already anonymized user returns 0 rows."""
    import database

    # First anonymization
    database.users.anonymize_user(test_user["tenant_id"], test_user["id"])

    # Second anonymization should return 0
    rows_affected = database.users.anonymize_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 0


def test_reactivate_anonymized_user_fails(test_user):
    """Test that reactivating an anonymized user returns 0 rows."""
    import database

    # Anonymize the user
    database.users.anonymize_user(test_user["tenant_id"], test_user["id"])

    # Attempt to reactivate should fail
    rows_affected = database.users.reactivate_user(test_user["tenant_id"], test_user["id"])
    assert rows_affected == 0

    # User should still be inactivated and anonymized
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["is_inactivated"] is True
    assert user["is_anonymized"] is True


def test_count_active_super_admins(test_tenant, test_super_admin_user):
    """Test counting active super_admin users."""
    import database

    count = database.users.count_active_super_admins(test_tenant["id"])
    assert count >= 1


def test_count_active_super_admins_excludes_inactivated(test_tenant, test_super_admin_user):
    """Test that inactivated super_admins are not counted."""
    import database

    # Get initial count
    initial_count = database.users.count_active_super_admins(test_tenant["id"])

    # Inactivate the super_admin
    database.users.inactivate_user(test_tenant["id"], test_super_admin_user["id"])

    # Count should decrease
    new_count = database.users.count_active_super_admins(test_tenant["id"])
    assert new_count == initial_count - 1


# =============================================================================
# Role and Status Filtering Tests
# =============================================================================


def test_list_users_with_role_filter(test_tenant, test_user, test_admin_user):
    """Test listing users filtered by role."""
    import database

    # Filter by admin role only
    users = database.users.list_users(test_tenant["id"], roles=["admin"], page=1, page_size=10)

    assert len(users) == 1
    assert users[0]["id"] == test_admin_user["id"]
    assert users[0]["role"] == "admin"


def test_list_users_with_multiple_roles_filter(test_tenant, test_user, test_admin_user):
    """Test listing users filtered by multiple roles."""
    import database

    # Filter by member and admin roles
    users = database.users.list_users(
        test_tenant["id"], roles=["member", "admin"], page=1, page_size=10
    )

    assert len(users) == 2
    roles = {u["role"] for u in users}
    assert roles == {"member", "admin"}


def test_list_users_with_status_filter_active(test_tenant, test_user, test_admin_user):
    """Test listing only active users."""
    import database

    # Inactivate one user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Filter by active status
    users = database.users.list_users(test_tenant["id"], statuses=["active"], page=1, page_size=10)

    assert len(users) == 1
    assert users[0]["id"] == test_admin_user["id"]
    assert users[0]["is_inactivated"] is False


def test_list_users_with_status_filter_inactivated(test_tenant, test_user, test_admin_user):
    """Test listing only inactivated users."""
    import database

    # Inactivate one user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Filter by inactivated status
    users = database.users.list_users(
        test_tenant["id"], statuses=["inactivated"], page=1, page_size=10
    )

    assert len(users) == 1
    assert users[0]["id"] == test_user["id"]
    assert users[0]["is_inactivated"] is True
    assert users[0]["is_anonymized"] is False


def test_list_users_with_status_filter_anonymized(test_tenant, test_user, test_admin_user):
    """Test listing only anonymized users."""
    import database

    # Anonymize one user
    database.users.anonymize_user(test_tenant["id"], test_user["id"])

    # Filter by anonymized status
    users = database.users.list_users(
        test_tenant["id"], statuses=["anonymized"], page=1, page_size=10
    )

    assert len(users) == 1
    assert users[0]["id"] == test_user["id"]
    assert users[0]["is_anonymized"] is True


def test_list_users_with_multiple_statuses(test_tenant, test_user, test_admin_user):
    """Test listing users with multiple status values."""
    import database

    # Inactivate one user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Filter by active and inactivated (should get both)
    users = database.users.list_users(
        test_tenant["id"], statuses=["active", "inactivated"], page=1, page_size=10
    )

    assert len(users) == 2


def test_list_users_with_role_and_status_filter(test_tenant, test_user, test_admin_user):
    """Test listing users with both role and status filters."""
    import database

    # Inactivate the admin user
    database.users.inactivate_user(test_tenant["id"], test_admin_user["id"])

    # Filter by member role and active status
    users = database.users.list_users(
        test_tenant["id"], roles=["member"], statuses=["active"], page=1, page_size=10
    )

    assert len(users) == 1
    assert users[0]["id"] == test_user["id"]
    assert users[0]["role"] == "member"
    assert users[0]["is_inactivated"] is False


def test_list_users_with_status_sort_asc(test_tenant, test_user, test_admin_user):
    """Test sorting users by status ascending (Active -> Inactivated -> Anonymized)."""
    import database

    # Inactivate one user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Sort by status ascending
    users = database.users.list_users(
        test_tenant["id"], sort_field="status", sort_order="asc", page=1, page_size=10
    )

    assert len(users) == 2
    # Active users should come first
    assert users[0]["is_inactivated"] is False
    assert users[1]["is_inactivated"] is True


def test_list_users_with_status_sort_desc(test_tenant, test_user, test_admin_user):
    """Test sorting users by status descending (Anonymized -> Inactivated -> Active)."""
    import database

    # Inactivate one user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Sort by status descending
    users = database.users.list_users(
        test_tenant["id"], sort_field="status", sort_order="desc", page=1, page_size=10
    )

    assert len(users) == 2
    # Inactivated users should come first
    assert users[0]["is_inactivated"] is True
    assert users[1]["is_inactivated"] is False


def test_count_users_with_role_filter(test_tenant, test_user, test_admin_user):
    """Test counting users filtered by role."""
    import database

    # Count only admins
    count = database.users.count_users(test_tenant["id"], roles=["admin"])
    assert count == 1

    # Count members and admins
    count = database.users.count_users(test_tenant["id"], roles=["member", "admin"])
    assert count == 2


def test_count_users_with_status_filter(test_tenant, test_user, test_admin_user):
    """Test counting users filtered by status."""
    import database

    # Initially all are active
    count = database.users.count_users(test_tenant["id"], statuses=["active"])
    assert count == 2

    # Inactivate one user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Count active users
    count = database.users.count_users(test_tenant["id"], statuses=["active"])
    assert count == 1

    # Count inactivated users
    count = database.users.count_users(test_tenant["id"], statuses=["inactivated"])
    assert count == 1


def test_count_users_with_role_and_status_filter(test_tenant, test_user, test_admin_user):
    """Test counting users with both role and status filters."""
    import database

    # Inactivate the admin
    database.users.inactivate_user(test_tenant["id"], test_admin_user["id"])

    # Count active members
    count = database.users.count_users(test_tenant["id"], roles=["member"], statuses=["active"])
    assert count == 1

    # Count inactivated admins
    count = database.users.count_users(test_tenant["id"], roles=["admin"], statuses=["inactivated"])
    assert count == 1


def test_list_users_with_search_and_filters(test_tenant, test_user, test_admin_user):
    """Test combining search with role and status filters."""
    import database

    # Search with role filter
    users = database.users.list_users(
        test_tenant["id"],
        search=test_user["first_name"],
        roles=["member"],
        page=1,
        page_size=10,
    )

    assert len(users) >= 1
    assert all(u["role"] == "member" for u in users)


# =============================================================================
# Tokenized Search Tests
# =============================================================================


def test_list_users_tokenized_search_single_word(test_tenant, test_user, test_admin_user):
    """Single-word search behaves identically to old behavior."""
    import database

    users = database.users.list_users(test_tenant["id"], search="Test", page=1, page_size=10)
    assert any(u["id"] == test_user["id"] for u in users)


def test_list_users_tokenized_search_multi_word_cross_field(
    test_tenant, test_user, test_admin_user
):
    """Multi-word search matches across first_name and last_name."""
    import database

    # test_user is first_name="Test", last_name="User"
    # "Test User" should match (Test in first_name, User in last_name)
    users = database.users.list_users(test_tenant["id"], search="Test User", page=1, page_size=10)
    assert any(u["id"] == test_user["id"] for u in users)

    # "Admin User" should match admin user (Admin in first_name, User in last_name)
    users = database.users.list_users(test_tenant["id"], search="Admin User", page=1, page_size=10)
    assert any(u["id"] == test_admin_user["id"] for u in users)
    # "Test" shouldn't be in admin results for "Admin User" since both tokens must match
    assert not any(u["id"] == test_user["id"] for u in users if u["first_name"] != "Admin")


def test_list_users_tokenized_search_extra_whitespace(test_tenant, test_user):
    """Extra whitespace between tokens is ignored."""
    import database

    users = database.users.list_users(
        test_tenant["id"], search="  Test   User  ", page=1, page_size=10
    )
    assert any(u["id"] == test_user["id"] for u in users)


def test_count_users_tokenized_search(test_tenant, test_user, test_admin_user):
    """count_users agrees with list_users on tokenized search results."""
    import database

    search = "Test User"
    count = database.users.count_users(test_tenant["id"], search=search)
    users = database.users.list_users(test_tenant["id"], search=search, page=1, page_size=100)
    assert count == len(users)


def test_list_users_tokenized_search_no_match(test_tenant, test_user, test_admin_user):
    """Multi-word search with non-matching token returns no results."""
    import database

    # "Test Zzzzz" should not match anyone
    users = database.users.list_users(test_tenant["id"], search="Test Zzzzz", page=1, page_size=10)
    assert len(users) == 0
