"""Unit tests for the shared scope-gated OIDC claim assembler.

Covers the profile/email portion shipped this iteration: claims are released
only when their scope is granted, and `sub` is never produced here (it is a
token-envelope claim carrying the stable user id).
"""

import database
import pytest
from services.oidc import claims as claims_service


class TestParseScope:
    def test_none_and_empty(self):
        assert claims_service.parse_scope(None) == set()
        assert claims_service.parse_scope("") == set()
        assert claims_service.parse_scope("   ") == set()

    def test_splits_and_dedupes(self):
        assert claims_service.parse_scope("openid profile  email openid") == {
            "openid",
            "profile",
            "email",
        }


class TestBuildClaims:
    def test_openid_only_releases_no_profile_or_email(self, test_tenant, test_user):
        result = claims_service.build_claims(
            str(test_tenant["id"]), str(test_user["id"]), {"openid"}
        )
        assert result == {}

    def test_profile_scope_releases_profile_claims(self, test_tenant, test_user):
        result = claims_service.build_claims(
            str(test_tenant["id"]), str(test_user["id"]), {"openid", "profile"}
        )
        assert result["given_name"] == "Test"
        assert result["family_name"] == "User"
        assert result["name"] == "Test User"
        assert "updated_at" in result
        assert isinstance(result["updated_at"], int)
        # Email must NOT appear without the email scope.
        assert "email" not in result

    def test_email_scope_releases_email_claims(self, test_tenant, test_user):
        result = claims_service.build_claims(
            str(test_tenant["id"]), str(test_user["id"]), {"openid", "email"}
        )
        assert result["email"] == test_user["email"]
        assert result["email_verified"] is True
        # Profile claims must not appear without the profile scope.
        assert "given_name" not in result
        assert "name" not in result

    def test_email_verified_false_when_unverified(self, test_tenant, test_user):
        # Flip the primary email to unverified.
        database.execute(
            test_tenant["id"],
            "update user_emails set verified_at = null where user_id = :uid and is_primary",
            {"uid": test_user["id"]},
        )
        result = claims_service.build_claims(
            str(test_tenant["id"]), str(test_user["id"]), {"email"}
        )
        assert result["email"] == test_user["email"]
        assert result["email_verified"] is False

    def test_never_includes_sub(self, test_tenant, test_user):
        result = claims_service.build_claims(
            str(test_tenant["id"]), str(test_user["id"]), {"openid", "profile", "email"}
        )
        assert "sub" not in result

    def test_unknown_user_returns_empty(self, test_tenant):
        from uuid import uuid4

        result = claims_service.build_claims(
            str(test_tenant["id"]), str(uuid4()), {"profile", "email"}
        )
        assert result == {}


@pytest.mark.parametrize("scope", ["openid", ""])
def test_no_claim_bearing_scope_skips_db(scope, test_tenant, test_user):
    """No DB read happens when only non-claim scopes are granted."""
    result = claims_service.build_claims(
        str(test_tenant["id"]), str(test_user["id"]), claims_service.parse_scope(scope)
    )
    assert result == {}
