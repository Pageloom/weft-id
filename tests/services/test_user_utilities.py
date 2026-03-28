"""Tests for services/users/utilities.py.

These functions are thin wrappers around database calls (no authorization),
used by auth flows and internal operations.
"""

from unittest.mock import patch
from uuid import uuid4

# =============================================================================
# check_collation_exists
# =============================================================================


def test_check_collation_exists_returns_true():
    """check_collation_exists delegates to database and returns True."""
    from services.users.utilities import check_collation_exists

    with patch("services.users.utilities.database") as mock_db:
        mock_db.users.check_collation_exists.return_value = True

        result = check_collation_exists("t1", "sv-SE-x-icu")

        assert result is True
        mock_db.users.check_collation_exists.assert_called_once_with("t1", "sv-SE-x-icu")


# =============================================================================
# count_users
# =============================================================================


def test_count_users_delegates_to_database():
    """count_users passes all filters through to database."""
    from services.users.utilities import count_users

    with patch("services.users.utilities.database") as mock_db:
        mock_db.users.count_users.return_value = 42

        result = count_users(
            "t1",
            search="jane",
            roles=["admin"],
            statuses=["active"],
            auth_methods=["password_email"],
        )

        assert result == 42
        mock_db.users.count_users.assert_called_once_with(
            "t1",
            "jane",
            ["admin"],
            ["active"],
            ["password_email"],
            domain=None,
            group_id=None,
            has_secondary_email=None,
            activity_start=None,
            activity_end=None,
        )


# =============================================================================
# list_users_raw
# =============================================================================


def test_list_users_raw_delegates_to_database():
    """list_users_raw passes pagination and filters to database."""
    from services.users.utilities import list_users_raw

    with patch("services.users.utilities.database") as mock_db:
        mock_db.users.list_users.return_value = [{"id": "u1"}]

        result = list_users_raw(
            "t1",
            search="x",
            sort_field="name",
            sort_order="asc",
            page=2,
            page_size=10,
            collation="en-US-x-icu",
            roles=["member"],
            statuses=["active"],
            auth_methods=["password_totp"],
        )

        assert result == [{"id": "u1"}]
        mock_db.users.list_users.assert_called_once_with(
            tenant_id="t1",
            search="x",
            sort_field="name",
            sort_order="asc",
            page=2,
            page_size=10,
            collation="en-US-x-icu",
            roles=["member"],
            statuses=["active"],
            auth_methods=["password_totp"],
            domain=None,
            group_id=None,
            has_secondary_email=None,
            activity_start=None,
            activity_end=None,
        )


# =============================================================================
# get_auth_method_options (IdP + TOTP branch)
# =============================================================================


def test_get_auth_method_options_includes_idp_with_totp():
    """get_auth_method_options adds IdP + TOTP option when require_platform_mfa is set."""
    from services.users.utilities import get_auth_method_options

    idp_id = str(uuid4())

    with patch("services.users.utilities.database") as mock_db:
        mock_db.saml.list_identity_providers.return_value = [
            {"id": idp_id, "name": "Okta Corp", "require_platform_mfa": True},
        ]

        options = get_auth_method_options("t1")

    keys = [o["auth_method_key"] for o in options]
    labels = [o["auth_method_label"] for o in options]

    # Should have: password_email, password_totp, idp:<id>, idp:<id>_totp, unverified
    assert "password_email" in keys
    assert "password_totp" in keys
    assert f"idp:{idp_id}" in keys
    assert f"idp:{idp_id}_totp" in keys
    assert "unverified" in keys
    assert "Okta Corp" in labels
    assert "Okta Corp + TOTP" in labels


def test_get_auth_method_options_idp_without_totp():
    """get_auth_method_options omits TOTP option when IdP doesn't require it."""
    from services.users.utilities import get_auth_method_options

    idp_id = str(uuid4())

    with patch("services.users.utilities.database") as mock_db:
        mock_db.saml.list_identity_providers.return_value = [
            {"id": idp_id, "name": "Google", "require_platform_mfa": False},
        ]

        options = get_auth_method_options("t1")

    keys = [o["auth_method_key"] for o in options]
    assert f"idp:{idp_id}" in keys
    assert f"idp:{idp_id}_totp" not in keys


# =============================================================================
# get_available_roles
# =============================================================================


def test_get_available_roles():
    """get_available_roles returns the three role names."""
    from services.users.utilities import get_available_roles

    assert get_available_roles() == ["member", "admin", "super_admin"]


# =============================================================================
# update_password
# =============================================================================


def test_update_password_delegates():
    """update_password calls database.users.update_password."""
    from services.users.utilities import update_password

    with patch("services.users.utilities.database") as mock_db:
        update_password("t1", "u1", "hash123")
        mock_db.users.update_password.assert_called_once_with(
            "t1",
            "u1",
            "hash123",
            hibp_prefix=None,
            hibp_check_hmac=None,
            policy_length_at_set=None,
            policy_score_at_set=None,
        )


# =============================================================================
# update_timezone_and_last_login
# =============================================================================


def test_update_timezone_and_last_login_delegates():
    """update_timezone_and_last_login calls database."""
    from services.users.utilities import update_timezone_and_last_login

    with patch("services.users.utilities.database") as mock_db:
        update_timezone_and_last_login("t1", "u1", "America/New_York")
        mock_db.users.update_timezone_and_last_login.assert_called_once_with(
            "t1", "u1", "America/New_York"
        )


# =============================================================================
# update_locale_and_last_login
# =============================================================================


def test_update_locale_and_last_login_delegates():
    """update_locale_and_last_login calls database."""
    from services.users.utilities import update_locale_and_last_login

    with patch("services.users.utilities.database") as mock_db:
        update_locale_and_last_login("t1", "u1", "en-US")
        mock_db.users.update_locale_and_last_login.assert_called_once_with("t1", "u1", "en-US")


# =============================================================================
# update_timezone_locale_and_last_login
# =============================================================================


def test_update_timezone_locale_and_last_login_delegates():
    """update_timezone_locale_and_last_login calls database."""
    from services.users.utilities import update_timezone_locale_and_last_login

    with patch("services.users.utilities.database") as mock_db:
        update_timezone_locale_and_last_login("t1", "u1", "Europe/London", "en-GB")
        mock_db.users.update_timezone_locale_and_last_login.assert_called_once_with(
            "t1", "u1", "Europe/London", "en-GB"
        )
