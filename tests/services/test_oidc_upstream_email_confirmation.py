"""Tests for email confirmation on untrusted-email providers.

Facebook and Microsoft personal accounts do not prove the user controls the
address they report. JIT stores it unverified and holds back domain group
assignment; the sign-in must then confirm it (services layer here, the route
in tests/routers/test_oidc_email_confirmation.py).
"""

from unittest.mock import patch

import database
import pytest
from services.oidc_upstream import email_confirmation
from services.oidc_upstream.connections import _encrypt_secret
from services.oidc_upstream.provisioning import authenticate_via_oidc

AUTO_ASSIGN = "services.settings.auto_assign_user_to_domain_groups"


def _connection(test_tenant, test_super_admin_user, provider_type="facebook", **flags):
    issuers = {
        "facebook": "https://www.facebook.com",
        "google": "https://accounts.google.com",
        "microsoft": "https://login.microsoftonline.com/9188040d/v2.0",
    }
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=provider_type.title(),
        provider_type=provider_type,
        issuer=issuers[provider_type],
        created_by=str(test_super_admin_user["id"]),
        client_id="client",
        client_secret_enc=_encrypt_secret("secret"),
        is_enabled=True,
        jit_provisioning=True,
        **flags,
    )


def _claims(email="newcomer@example.com", **extra):
    return {
        "sub": "fb-1",
        "email": email,
        "email_verified": False,
        "given_name": "New",
        "family_name": "Comer",
        **extra,
    }


def _sign_in(tenant_id, connection, claims=None, sub="fb-1"):
    return authenticate_via_oidc(
        tenant_id=str(tenant_id),
        connection=connection,
        sub=sub,
        claims=claims or _claims(),
    )


def _primary(tenant_id, user_id):
    return database.user_emails.get_primary_email_for_resend(tenant_id, str(user_id))


class TestRequiresConfirmedEmail:
    @pytest.mark.parametrize(
        ("provider_type", "expected"),
        [
            ("facebook", True),
            ("microsoft", True),
            ("google", False),
            ("github", False),
            ("discord", False),
            ("generic", False),
            ("apple", False),
            # No preset: fails closed, like email linking.
            ("nonexistent", True),
            (None, True),
        ],
    )
    def test_by_provider(self, provider_type, expected):
        assert email_confirmation.requires_confirmed_email(provider_type) is expected


class TestJIT:
    def test_untrusted_jit_stores_email_unverified(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user)
        with patch(AUTO_ASSIGN) as auto_assign:
            user = _sign_in(test_tenant["id"], row)

        primary = _primary(test_tenant["id"], user["id"])
        assert primary["email"] == "newcomer@example.com"
        assert primary["verified_at"] is None
        # The unproven domain grants nothing yet.
        auto_assign.assert_not_called()

        events = database.event_log.list_events(test_tenant["id"], limit=20)
        jit = next(e for e in events if e["event_type"] == "oidc_user_jit_provisioned")
        assert jit["metadata"]["email_verified"] is False

    def test_trusted_jit_unchanged(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user, provider_type="google")
        with patch(AUTO_ASSIGN) as auto_assign:
            user = _sign_in(test_tenant["id"], row, _claims(email_verified=True))

        assert _primary(test_tenant["id"], user["id"])["verified_at"] is not None
        auto_assign.assert_called_once()
        events = database.event_log.list_events(test_tenant["id"], limit=20)
        jit = next(e for e in events if e["event_type"] == "oidc_user_jit_provisioned")
        assert jit["metadata"]["email_verified"] is True

    def test_microsoft_personal_also_unverified(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user, provider_type="microsoft")
        user = _sign_in(test_tenant["id"], row)
        assert _primary(test_tenant["id"], user["id"])["verified_at"] is None


class TestPendingEmailConfirmation:
    def test_pending_after_untrusted_jit(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user)
        user = _sign_in(test_tenant["id"], row)

        pending = email_confirmation.pending_email_confirmation(
            str(test_tenant["id"]), row, str(user["id"])
        )
        primary = _primary(test_tenant["id"], user["id"])
        assert pending == {"email_id": str(primary["id"]), "email": "newcomer@example.com"}

    def test_still_pending_on_the_next_sign_in(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user)
        user = _sign_in(test_tenant["id"], row)
        # Existing-link branch: the address is still unconfirmed.
        again = _sign_in(test_tenant["id"], row)
        assert str(again["id"]) == str(user["id"])
        assert email_confirmation.pending_email_confirmation(
            str(test_tenant["id"]), row, str(user["id"])
        )

    def test_none_for_a_trusted_connection(self, test_tenant, test_super_admin_user, test_user):
        row = _connection(test_tenant, test_super_admin_user, provider_type="google")
        assert (
            email_confirmation.pending_email_confirmation(
                str(test_tenant["id"]), row, str(test_user["id"])
            )
            is None
        )

    def test_none_for_a_verified_address(self, test_tenant, test_super_admin_user, test_user):
        row = _connection(test_tenant, test_super_admin_user)
        # test_user's primary address is verified.
        assert _primary(test_tenant["id"], test_user["id"])["verified_at"] is not None
        assert (
            email_confirmation.pending_email_confirmation(
                str(test_tenant["id"]), row, str(test_user["id"])
            )
            is None
        )


class TestConfirmSignInEmail:
    def test_confirms_logs_and_assigns_groups(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user)
        user = _sign_in(test_tenant["id"], row)
        user_id = str(user["id"])
        pending = email_confirmation.pending_email_confirmation(
            str(test_tenant["id"]), row, user_id
        )

        with patch(AUTO_ASSIGN) as auto_assign:
            email_confirmation.confirm_sign_in_email(
                str(test_tenant["id"]), user_id, pending["email_id"], str(row["id"])
            )

        assert _primary(test_tenant["id"], user_id)["verified_at"] is not None
        auto_assign.assert_called_once_with(
            str(test_tenant["id"]), user_id, "newcomer@example.com", user_id
        )
        assert (
            email_confirmation.pending_email_confirmation(str(test_tenant["id"]), row, user_id)
            is None
        )
        events = database.event_log.list_events(test_tenant["id"], limit=20)
        verified = next(e for e in events if e["event_type"] == "email_verified")
        assert {
            "email_id": pending["email_id"],
            "email": "newcomer@example.com",
            "flow": "oidc_sign_in",
            "idp_id": str(row["id"]),
        }.items() <= verified["metadata"].items()
        assert str(verified["actor_user_id"]) == user_id

    def test_wrong_email_id_is_a_no_op(self, test_tenant, test_super_admin_user):
        row = _connection(test_tenant, test_super_admin_user)
        user = _sign_in(test_tenant["id"], row)
        with patch(AUTO_ASSIGN) as auto_assign:
            email_confirmation.confirm_sign_in_email(
                str(test_tenant["id"]),
                str(user["id"]),
                "00000000-0000-0000-0000-000000000000",
                str(row["id"]),
            )
        assert _primary(test_tenant["id"], user["id"])["verified_at"] is None
        auto_assign.assert_not_called()

    def test_already_verified_is_a_no_op(self, test_tenant, test_super_admin_user, test_user):
        row = _connection(test_tenant, test_super_admin_user)
        primary = _primary(test_tenant["id"], test_user["id"])
        with patch(AUTO_ASSIGN) as auto_assign:
            email_confirmation.confirm_sign_in_email(
                str(test_tenant["id"]), str(test_user["id"]), str(primary["id"]), str(row["id"])
            )
        auto_assign.assert_not_called()
        events = database.event_log.list_events(test_tenant["id"], limit=20)
        assert not any(e["event_type"] == "email_verified" for e in events)
