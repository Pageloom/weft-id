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


def test_list_users_search_escapes_like_wildcards(test_user):
    """Test that % and _ in search terms are treated as literals, not SQL wildcards."""
    import database

    # Search with underscore - should not match single-char wildcard
    users = database.users.list_users(test_user["tenant_id"], search="user_1", page=1, page_size=10)
    # "user_1" should only match literal "user_1", not "usera1", "userb1", etc.
    for u in users:
        full = f"{u['first_name']} {u['last_name']} {u.get('email', '')}"
        assert "user_1" in full.lower() or "_" in full

    # Search with percent - should not match multi-char wildcard
    users = database.users.list_users(test_user["tenant_id"], search="100%", page=1, page_size=10)
    assert len(users) == 0  # No user named "100%"

    # Count should match
    count = database.users.count_users(test_user["tenant_id"], search="100%")
    assert count == 0


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

    # Should be set (or updated) after calling update_last_login
    assert user_after["last_login"] is not None
    if initial_last_login is not None:
        assert user_after["last_login"] >= initial_last_login


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


# =============================================================================
# Auth Method Filter and Counts Tests
# =============================================================================


def test_list_users_filter_by_password_email(test_tenant, test_user, test_admin_user):
    """Filter by password_email auth method returns users with password but no TOTP."""
    import database

    users = database.users.list_users(
        test_tenant["id"], auth_methods=["password_email"], page=1, page_size=10
    )
    assert len(users) == 2  # Both test users have passwords, no TOTP
    for u in users:
        assert u["has_password"] is True


def test_count_users_filter_by_auth_method(test_tenant, test_user, test_admin_user):
    """count_users with auth_methods filter matches list_users."""
    import database

    count = database.users.count_users(test_tenant["id"], auth_methods=["password_email"])
    users = database.users.list_users(
        test_tenant["id"], auth_methods=["password_email"], page=1, page_size=100
    )
    assert count == len(users)


def test_list_users_filter_by_unverified(test_tenant, test_user, test_admin_user):
    """Filter by unverified returns only users without password and without IdP."""
    import database

    # No unverified users in our test data (both have passwords)
    users = database.users.list_users(
        test_tenant["id"], auth_methods=["unverified"], page=1, page_size=10
    )
    assert len(users) == 0


def test_list_users_filter_auth_method_combined_with_search(
    test_tenant, test_user, test_admin_user
):
    """Auth method filter works together with search."""
    import database

    users = database.users.list_users(
        test_tenant["id"],
        search="Test",
        auth_methods=["password_email"],
        page=1,
        page_size=10,
    )
    assert len(users) >= 1
    assert all(u["has_password"] is True for u in users)


def test_list_users_filter_auth_method_combined_with_role(test_tenant, test_user, test_admin_user):
    """Auth method filter works together with role filter."""
    import database

    users = database.users.list_users(
        test_tenant["id"],
        roles=["admin"],
        auth_methods=["password_email"],
        page=1,
        page_size=10,
    )
    assert len(users) == 1
    assert users[0]["role"] == "admin"
    assert users[0]["has_password"] is True


def test_list_users_excludes_service_accounts(test_tenant, test_user, test_admin_user):
    """Service accounts (B2B OAuth2 clients) are excluded from user listing."""
    import database

    # Baseline: two regular users
    users_before = database.users.list_users(test_tenant["id"], page=1, page_size=100)
    count_before = database.users.count_users(test_tenant["id"])
    assert len(users_before) == 2
    assert count_before == 2

    # Create a B2B client (which creates a service user)
    client = database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test B2B App",
        role="member",
        created_by=str(test_admin_user["id"]),
    )
    assert client is not None
    assert client["service_user_id"] is not None

    # Service user should NOT appear in list or count
    users_after = database.users.list_users(test_tenant["id"], page=1, page_size=100)
    count_after = database.users.count_users(test_tenant["id"])
    assert len(users_after) == 2
    assert count_after == 2
    assert not any(str(u["id"]) == str(client["service_user_id"]) for u in users_after)


def test_count_users_excludes_service_accounts(test_tenant, test_user, test_admin_user):
    """count_users excludes service accounts and agrees with list_users."""
    import database

    # Create a B2B client
    database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Counter B2B App",
        role="admin",
        created_by=str(test_admin_user["id"]),
    )

    # Count should match list length, both excluding service user
    count = database.users.count_users(test_tenant["id"])
    users = database.users.list_users(test_tenant["id"], page=1, page_size=100)
    assert count == len(users)
    assert count == 2  # Only the two regular users


def test_list_users_includes_group_count(test_tenant, test_user, test_admin_user):
    """list_users includes group_count field showing number of group memberships."""
    import database

    users = database.users.list_users(test_tenant["id"], page=1, page_size=100)

    # All users should have group_count field
    for u in users:
        assert "group_count" in u
        assert isinstance(u["group_count"], int)

    # Initially zero groups
    test_u = next(u for u in users if u["id"] == test_user["id"])
    assert test_u["group_count"] == 0

    # Create a group and add user to it
    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test Group for Count",
        group_type="weftid",
        created_by=str(test_admin_user["id"]),
    )
    database.groups.add_group_member(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        group_id=str(group["id"]),
        user_id=str(test_user["id"]),
    )

    # Verify group_count is now 1
    users_after = database.users.list_users(test_tenant["id"], page=1, page_size=100)
    test_u_after = next(u for u in users_after if u["id"] == test_user["id"])
    assert test_u_after["group_count"] == 1

    # Admin should still have 0
    admin_u = next(u for u in users_after if u["id"] == test_admin_user["id"])
    assert admin_u["group_count"] == 0


# =============================================================================
# SAML Assignment Tests (database.users.saml_assignment)
# =============================================================================


def _create_saml_idp(tenant, user, name="Test IdP"):
    """Create a SAML IdP record for testing."""
    from uuid import uuid4

    import database

    unique_entity_id = f"https://idp-{uuid4().hex[:8]}.example.com"
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
        ) RETURNING id, name
        """,
        {
            "tenant_id": tenant["id"],
            "name": name,
            "entity_id": unique_entity_id,
            "created_by": user["id"],
        },
    )


# -- get_user_auth_info -------------------------------------------------------


def test_get_user_auth_info_returns_auth_routing_fields(test_tenant, test_user):
    """Test that get_user_auth_info returns correct routing info for a user with a password."""
    import database

    result = database.users.get_user_auth_info(test_tenant["id"], test_user["email"])

    assert result is not None
    assert result["has_password"] is True
    assert result["saml_idp_id"] is None
    assert result["is_inactivated"] is False
    assert str(result["id"]) == str(test_user["id"])


def test_get_user_auth_info_with_idp_assigned(test_tenant, test_user):
    """Test that get_user_auth_info returns the assigned saml_idp_id."""
    import database

    idp = _create_saml_idp(test_tenant, test_user, name="Auth Info IdP")
    database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp["id"]))

    result = database.users.get_user_auth_info(test_tenant["id"], test_user["email"])

    assert result is not None
    assert str(result["saml_idp_id"]) == str(idp["id"])
    assert result["has_password"] is True


def test_get_user_auth_info_returns_none_for_unverified_email(test_tenant, test_user):
    """Test that get_user_auth_info returns None when the email is not verified."""
    import database

    # Unverify the user's email
    database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    result = database.users.get_user_auth_info(test_tenant["id"], test_user["email"])

    assert result is None


def test_get_user_auth_info_returns_none_for_unknown_email(test_tenant):
    """Test that get_user_auth_info returns None for an unrecognised email."""
    import database

    result = database.users.get_user_auth_info(test_tenant["id"], "nobody@example.com")

    assert result is None


# -- wipe_user_password -------------------------------------------------------


def test_wipe_user_password_nulls_hash(test_tenant, test_user):
    """Test that wipe_user_password sets password_hash to null."""
    import database

    rows = database.users.wipe_user_password(test_tenant["id"], str(test_user["id"]))

    assert rows == 1

    result = database.users.get_user_auth_info(test_tenant["id"], test_user["email"])
    assert result is not None
    assert result["has_password"] is False


def test_wipe_user_password_idempotent(test_tenant, test_user):
    """Test that wiping an already-null password still returns 1 row affected."""
    import database

    database.users.wipe_user_password(test_tenant["id"], str(test_user["id"]))
    # Second wipe - row still exists, so UPDATE touches it
    rows = database.users.wipe_user_password(test_tenant["id"], str(test_user["id"]))

    assert rows == 1


# -- unverify_user_emails -----------------------------------------------------


def test_unverify_user_emails_clears_verified_at(test_tenant, test_user):
    """Test that unverify_user_emails nulls verified_at for the user's emails."""
    import database

    rows = database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    assert rows == 1

    # get_user_auth_info requires verified_at is not null - should return None now
    result = database.users.get_user_auth_info(test_tenant["id"], test_user["email"])
    assert result is None


def test_unverify_user_emails_regenerates_verify_nonce(test_tenant, test_user):
    """Test that unverify_user_emails regenerates the verify_nonce."""
    import database

    before = database.fetchone(
        test_tenant["id"],
        "SELECT verify_nonce FROM user_emails WHERE user_id = :user_id",
        {"user_id": str(test_user["id"])},
    )
    nonce_before = before["verify_nonce"]

    database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    after = database.fetchone(
        test_tenant["id"],
        "SELECT verify_nonce FROM user_emails WHERE user_id = :user_id",
        {"user_id": str(test_user["id"])},
    )
    assert after["verify_nonce"] != nonce_before
    assert isinstance(after["verify_nonce"], str)
    assert len(after["verify_nonce"]) == 48


def test_unverify_user_emails_skips_already_unverified(test_tenant, test_user):
    """Test that already-unverified emails are not double-unverified (0 rows)."""
    import database

    # First call unverifies
    database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    # Second call should affect 0 rows (verified_at is already null)
    rows = database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))
    assert rows == 0


# -- get_users_by_email_domain ------------------------------------------------


def test_get_users_by_email_domain_returns_matching_users(test_tenant, test_user):
    """Test that get_users_by_email_domain finds users with verified domain emails."""
    import database

    domain = test_user["email"].split("@")[1]
    results = database.users.get_users_by_email_domain(test_tenant["id"], domain)

    user_ids = [str(r["id"]) for r in results]
    assert str(test_user["id"]) in user_ids

    # Verify shape
    row = next(r for r in results if str(r["id"]) == str(test_user["id"]))
    assert "has_password" in row
    assert "saml_idp_id" in row
    assert row["has_password"] is True


def test_get_users_by_email_domain_excludes_unverified(test_tenant, test_user):
    """Test that users with unverified domain emails are excluded."""
    import database

    domain = test_user["email"].split("@")[1]
    database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    results = database.users.get_users_by_email_domain(test_tenant["id"], domain)

    user_ids = [str(r["id"]) for r in results]
    assert str(test_user["id"]) not in user_ids


def test_get_users_by_email_domain_empty_for_unknown_domain(test_tenant):
    """Test that an unknown domain returns an empty list."""
    import database

    results = database.users.get_users_by_email_domain(test_tenant["id"], "unknowndomain.invalid")

    assert results == []


# -- bulk_assign_users_to_idp -------------------------------------------------


def test_bulk_assign_users_to_idp_updates_all(test_tenant, test_user, test_admin_user):
    """Test that bulk_assign_users_to_idp sets saml_idp_id for all given users."""
    import database

    idp = _create_saml_idp(test_tenant, test_user, name="Bulk Assign IdP")
    user_ids = [str(test_user["id"]), str(test_admin_user["id"])]

    rows = database.users.bulk_assign_users_to_idp(test_tenant["id"], user_ids, str(idp["id"]))

    assert rows == 2

    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    admin = database.users.get_user_by_id(test_tenant["id"], test_admin_user["id"])
    assert str(user["saml_idp_id"]) == str(idp["id"])
    assert str(admin["saml_idp_id"]) == str(idp["id"])


def test_bulk_assign_users_to_idp_empty_list(test_tenant, test_user):
    """Test that an empty user_ids list returns 0 immediately without touching the DB."""
    import database

    rows = database.users.bulk_assign_users_to_idp(test_tenant["id"], [], "any-idp-id")

    assert rows == 0


# -- bulk_inactivate_users ----------------------------------------------------


def test_bulk_inactivate_users_sets_flags_and_clears_idp(test_tenant, test_user, test_admin_user):
    """Test that bulk_inactivate_users sets is_inactivated and clears saml_idp_id."""
    import database

    idp = _create_saml_idp(test_tenant, test_user, name="Bulk Inactivate IdP")
    database.users.bulk_assign_users_to_idp(
        test_tenant["id"],
        [str(test_user["id"]), str(test_admin_user["id"])],
        str(idp["id"]),
    )

    rows = database.users.bulk_inactivate_users(
        test_tenant["id"], [str(test_user["id"]), str(test_admin_user["id"])]
    )

    assert rows == 2

    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    admin = database.users.get_user_by_id(test_tenant["id"], test_admin_user["id"])
    assert user["is_inactivated"] is True
    assert user["saml_idp_id"] is None
    assert admin["is_inactivated"] is True
    assert admin["saml_idp_id"] is None


def test_bulk_inactivate_users_empty_list(test_tenant, test_user):
    """Test that an empty user_ids list returns 0 immediately."""
    import database

    rows = database.users.bulk_inactivate_users(test_tenant["id"], [])

    assert rows == 0


# -- bulk_unverify_emails -----------------------------------------------------


def test_bulk_unverify_emails_clears_verified_at(test_tenant, test_user, test_admin_user):
    """Test that bulk_unverify_emails nulls verified_at for all given users."""
    import database

    user_ids = [str(test_user["id"]), str(test_admin_user["id"])]
    rows = database.users.bulk_unverify_emails(test_tenant["id"], user_ids)

    assert rows == 2

    # Both users' emails should now be unverified
    assert database.users.get_user_auth_info(test_tenant["id"], test_user["email"]) is None
    assert database.users.get_user_auth_info(test_tenant["id"], test_admin_user["email"]) is None


def test_bulk_unverify_emails_skips_already_unverified(test_tenant, test_user, test_admin_user):
    """Test that already-unverified emails are excluded from the update count."""
    import database

    # Pre-unverify one user
    database.users.unverify_user_emails(test_tenant["id"], str(test_user["id"]))

    # Only admin's email is still verified - should get 1 row
    rows = database.users.bulk_unverify_emails(
        test_tenant["id"], [str(test_user["id"]), str(test_admin_user["id"])]
    )

    assert rows == 1


def test_bulk_unverify_emails_empty_list(test_tenant):
    """Test that an empty user_ids list returns 0 immediately."""
    import database

    rows = database.users.bulk_unverify_emails(test_tenant["id"], [])

    assert rows == 0
