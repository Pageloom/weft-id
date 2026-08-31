"""Tests for OIDC upstream JIT provisioning and authentication completion.

Covers each correlation branch: existing link, email-link allowed/disallowed,
email-link with email_verified false, JIT, JIT disabled, and inactivated-user
rejection.
"""

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError


def _make_connection(test_tenant, test_user, **overrides):
    import database

    created_by = str(test_user["id"])
    row = database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test OIDC",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=created_by,
        **overrides,
    )
    return row


def _claims(**overrides):
    claims = {
        "sub": "subject-123",
        "email": "oidc-user@example.com",
        "email_verified": True,
        "given_name": "Oidc",
        "family_name": "User",
    }
    claims.update(overrides)
    return claims


class TestExistingLink:
    def test_existing_link_authenticates_user(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )

        user = svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())
        assert str(user["id"]) == str(test_user["id"])

    def test_existing_link_inactivated_rejected(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        database.users.inactivate_user(test_tenant["id"], str(test_user["id"]))

        with pytest.raises(ForbiddenError) as exc_info:
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())
        assert exc_info.value.code == "user_inactivated"


class TestEmailLinking:
    def test_email_linking_allowed_links_existing(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, allow_email_linking=True)
        claims = _claims(email=test_user["email"])

        user = svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", claims)
        assert str(user["id"]) == str(test_user["id"])

        # A link row was created.
        linked = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        )
        assert linked == str(test_user["id"])

    def test_email_linking_disallowed_never_links(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, allow_email_linking=False)
        claims = _claims(email=test_user["email"])

        with pytest.raises(NotFoundError):
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", claims)

        assert (
            database.oidc_upstream.get_user_id_by_sub(
                test_tenant["id"], str(conn["id"]), "subject-123"
            )
            is None
        )

    def test_email_linking_requires_email_verified(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, allow_email_linking=True)
        claims = _claims(email=test_user["email"], email_verified=False)

        with pytest.raises(NotFoundError):
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", claims)

        assert (
            database.oidc_upstream.get_user_id_by_sub(
                test_tenant["id"], str(conn["id"]), "subject-123"
            )
            is None
        )


class TestJit:
    def test_jit_provisions_new_user(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        user = svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())

        assert user is not None
        assert user["id"] is not None

        linked = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        )
        assert linked == str(user["id"])

    def test_jit_disabled_rejects(self, test_tenant, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, jit_provisioning=False)
        with pytest.raises(NotFoundError) as exc_info:
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())
        assert exc_info.value.code == "user_not_found"

    def test_jit_invalid_email_rejected(self, test_tenant, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        claims = _claims(email="not-an-email")
        with pytest.raises(ValidationError) as exc_info:
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", claims)
        assert exc_info.value.code == "oidc_jit_invalid_email"

    def test_jit_email_exists_rejected_not_linked(self, test_tenant, test_user):
        """JIT must never attach to a pre-existing account (account-takeover guard).

        When the IdP presents an email already claimed by another account and
        allow_email_linking is off, JIT must reject rather than silently
        authenticate as that account.
        """
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(
            test_tenant, test_user, jit_provisioning=True, allow_email_linking=False
        )
        claims = _claims(email=test_user["email"])

        with pytest.raises(ValidationError) as exc_info:
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", claims)
        assert exc_info.value.code == "oidc_jit_email_exists"

        # No link was created for the unrecognized subject.
        assert (
            database.oidc_upstream.get_user_id_by_sub(
                test_tenant["id"], str(conn["id"]), "subject-123"
            )
            is None
        )


class TestCorrelationClaim:
    def test_correlation_uses_configured_claim(self, test_tenant, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(
            test_tenant, test_user, correlation_claim="oid", jit_provisioning=True
        )
        claims = _claims(oid="entra-oid-123")
        user = svc.authenticate_via_oidc(test_tenant["id"], conn, "entra-oid-123", claims)

        linked = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "entra-oid-123"
        )
        assert linked == str(user["id"])
