"""Tests for many OIDC identities per user and the account-linking policy.

Covers: email-first routing across several links (most recently used enabled
link wins), ``last_used_at`` stamping on every sign-in branch, refusal of
SAML-assigned users, one link per user per connection, the per-provider
email-linking trust rule, the admin list of a user's links, and per-link
unlink (only the last link deactivates).
"""

from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.types import RequestingUser


@pytest.fixture
def second_tenant():
    """A second tenant, deleted afterwards."""
    import database

    tenant = database.fetchone(
        database.UNSCOPED,
        "insert into tenants (subdomain, name) values (:s, 'Second') returning id",
        {"s": f"second-{uuid4().hex[:8]}"},
    )
    yield tenant
    database.execute(database.UNSCOPED, "delete from tenants where id = :id", {"id": tenant["id"]})


def _requesting(user, tenant_id, role="super_admin"):
    return RequestingUser(id=str(user["id"]), tenant_id=str(tenant_id), role=role)


def _make_connection(test_tenant, created_by, **overrides):
    import database

    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=overrides.pop("name", "Multi OIDC"),
        provider_type=overrides.pop("provider_type", "generic"),
        issuer=overrides.pop("issuer", "https://idp.example.com"),
        created_by=str(created_by["id"]),
        **overrides,
    )


def _link(test_tenant, connection, user, sub="subject-123"):
    import database

    return database.oidc_upstream.create_link(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        idp_id=str(connection["id"]),
        sub=sub,
        user_id=str(user["id"]),
    )


def _set_last_used(test_tenant, connection, sub, ago):
    """Backdate a link's last_used_at by an SQL interval string."""
    from database._core import execute

    execute(
        test_tenant["id"],
        f"update oidc_idp_user_links set last_used_at = now() - interval '{ago}' "
        "where idp_id = :idp_id and sub = :sub",
        {"idp_id": str(connection["id"]), "sub": sub},
    )


def _assign_saml(test_tenant, test_super_admin_user, user):
    import database

    idp = database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Corp SAML",
        provider_type="okta",
        sp_entity_id=f"https://sp.example.com/{uuid4()}",
        created_by=str(test_super_admin_user["id"]),
        is_enabled=True,
    )
    database.users.update_user_saml_idp(test_tenant["id"], str(user["id"]), str(idp["id"]))
    return idp


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


def _events(test_tenant, event_type, artifact_id):
    import database

    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=100)
        if e["event_type"] == event_type and str(e["artifact_id"]) == str(artifact_id)
    ]


def _link_row(test_tenant, connection, sub):
    import database

    return database.oidc_upstream.get_link_by_idp_sub(test_tenant["id"], str(connection["id"]), sub)


# =============================================================================
# Database layer
# =============================================================================


class TestLinkConstraints:
    def test_second_link_on_same_connection_rejected(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import psycopg

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user, sub="first")
        with pytest.raises(psycopg.errors.UniqueViolation):
            _link(test_tenant, conn, test_user, sub="second")

    def test_links_to_different_connections_allowed(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import database

        a = _make_connection(test_tenant, test_super_admin_user, name="A")
        b = _make_connection(test_tenant, test_super_admin_user, name="B")
        _link(test_tenant, a, test_user, sub="same-sub")
        _link(test_tenant, b, test_user, sub="same-sub")

        rows = database.oidc_upstream.list_links_for_user(test_tenant["id"], str(test_user["id"]))
        assert {str(r["idp_id"]) for r in rows} == {str(a["id"]), str(b["id"])}

    def test_list_links_order_and_connection_fields(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import database

        never = _make_connection(test_tenant, test_super_admin_user, name="Never used")
        old = _make_connection(test_tenant, test_super_admin_user, name="Old", is_enabled=True)
        recent = _make_connection(test_tenant, test_super_admin_user, name="Recent")
        _link(test_tenant, never, test_user, sub="n")
        _link(test_tenant, old, test_user, sub="o")
        _link(test_tenant, recent, test_user, sub="r")
        _set_last_used(test_tenant, old, "o", "2 days")
        _set_last_used(test_tenant, recent, "r", "1 hour")

        rows = database.oidc_upstream.list_links_for_user(test_tenant["id"], str(test_user["id"]))
        assert [r["connection_name"] for r in rows] == ["Recent", "Old", "Never used"]
        assert rows[1]["connection_enabled"] is True
        assert rows[0]["connection_enabled"] is False
        assert rows[0]["provider_type"] == "generic"

    def test_list_links_for_user_without_links(self, test_tenant, test_user):
        import database

        assert (
            database.oidc_upstream.list_links_for_user(test_tenant["id"], str(test_user["id"]))
            == []
        )

    def test_touch_link_sets_last_used(self, test_tenant, test_super_admin_user, test_user):
        import database

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)
        assert _link_row(test_tenant, conn, "subject-123")["last_used_at"] is None

        assert (
            database.oidc_upstream.touch_link(test_tenant["id"], str(conn["id"]), "subject-123")
            == 1
        )
        assert _link_row(test_tenant, conn, "subject-123")["last_used_at"] is not None

    def test_get_and_delete_link_for_user_idp(self, test_tenant, test_super_admin_user, test_user):
        import database

        conn = _make_connection(test_tenant, test_super_admin_user)
        tid, uid, cid = test_tenant["id"], str(test_user["id"]), str(conn["id"])
        assert database.oidc_upstream.get_link_for_user_idp(tid, uid, cid) is None

        _link(test_tenant, conn, test_user)
        assert database.oidc_upstream.get_link_for_user_idp(tid, uid, cid)["sub"] == "subject-123"

        assert database.oidc_upstream.delete_link_for_user_idp(tid, uid, cid) == 1
        assert database.oidc_upstream.get_link_for_user_idp(tid, uid, cid) is None


# =============================================================================
# Email-first routing
# =============================================================================


class TestRoutingAcrossLinks:
    def test_routes_to_most_recently_used_link(self, test_tenant, test_super_admin_user, test_user):
        from services.auth_routing import determine_auth_route

        a = _make_connection(test_tenant, test_super_admin_user, name="A", is_enabled=True)
        b = _make_connection(test_tenant, test_super_admin_user, name="B", is_enabled=True)
        _link(test_tenant, a, test_user, sub="a")
        _link(test_tenant, b, test_user, sub="b")
        _set_last_used(test_tenant, a, "a", "1 minute")
        _set_last_used(test_tenant, b, "b", "1 day")

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.route_type == "idp_oidc"
        assert result.idp_id == str(a["id"])
        assert result.idp_name == "A"
        assert result.user_id == str(test_user["id"])

    def test_skips_disabled_connection(self, test_tenant, test_super_admin_user, test_user):
        from services.auth_routing import determine_auth_route

        disabled = _make_connection(test_tenant, test_super_admin_user, name="Off")
        enabled = _make_connection(test_tenant, test_super_admin_user, name="On", is_enabled=True)
        _link(test_tenant, disabled, test_user, sub="off")
        _link(test_tenant, enabled, test_user, sub="on")
        _set_last_used(test_tenant, disabled, "off", "1 minute")
        _set_last_used(test_tenant, enabled, "on", "1 day")

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.route_type == "idp_oidc"
        assert result.idp_id == str(enabled["id"])

    def test_never_used_link_still_routes(self, test_tenant, test_super_admin_user, test_user):
        from services.auth_routing import determine_auth_route

        disabled = _make_connection(test_tenant, test_super_admin_user, name="Off")
        unused = _make_connection(
            test_tenant, test_super_admin_user, name="Unused", is_enabled=True
        )
        _link(test_tenant, disabled, test_user, sub="off")
        _link(test_tenant, unused, test_user, sub="unused")
        _set_last_used(test_tenant, disabled, "off", "1 minute")

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.idp_id == str(unused["id"])

    def test_all_links_disabled(self, test_tenant, test_super_admin_user, test_user):
        from services.auth_routing import determine_auth_route

        a = _make_connection(test_tenant, test_super_admin_user, name="A")
        b = _make_connection(test_tenant, test_super_admin_user, name="B")
        _link(test_tenant, a, test_user, sub="a")
        _link(test_tenant, b, test_user, sub="b")

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.route_type == "idp_oidc_disabled"
        assert result.user_id == str(test_user["id"])


# =============================================================================
# Sign-in: last_used_at, several links, refusals
# =============================================================================


class TestSignInStampsLastUsed:
    def test_existing_link(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())
        assert _link_row(test_tenant, conn, "subject-123")["last_used_at"] is not None

    def test_email_link(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user, allow_email_linking=True)
        svc.authenticate_via_oidc(
            test_tenant["id"], conn, "subject-123", _claims(email=test_user["email"])
        )
        assert _link_row(test_tenant, conn, "subject-123")["last_used_at"] is not None

    def test_jit(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user, jit_provisioning=True)
        svc.authenticate_via_oidc(
            test_tenant["id"], conn, "jit-sub", _claims(email="jit-multi@example.com")
        )
        assert _link_row(test_tenant, conn, "jit-sub")["last_used_at"] is not None


class TestSeveralLinks:
    def test_email_link_adds_second_connection(self, test_tenant, test_super_admin_user, test_user):
        """A user linked to A can email-link B; both then authenticate them."""
        from services import oidc_upstream as svc

        a = _make_connection(test_tenant, test_super_admin_user, name="A")
        b = _make_connection(test_tenant, test_super_admin_user, name="B", allow_email_linking=True)
        _link(test_tenant, a, test_user, sub="a-sub")

        via_b = svc.authenticate_via_oidc(
            test_tenant["id"], b, "b-sub", _claims(email=test_user["email"])
        )
        via_a = svc.authenticate_via_oidc(test_tenant["id"], a, "a-sub", _claims())

        assert str(via_b["id"]) == str(test_user["id"])
        assert str(via_a["id"]) == str(test_user["id"])

    def test_email_link_refused_when_already_linked_on_connection(
        self, test_tenant, test_super_admin_user, test_user
    ):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user, allow_email_linking=True)
        _link(test_tenant, conn, test_user, sub="original-sub")

        with pytest.raises(ForbiddenError) as exc_info:
            svc.authenticate_via_oidc(
                test_tenant["id"], conn, "other-sub", _claims(email=test_user["email"])
            )
        assert exc_info.value.code == "oidc_connection_already_linked"
        assert _link_row(test_tenant, conn, "other-sub") is None

        refused = _events(test_tenant, "oidc_login_refused", test_user["id"])
        assert len(refused) == 1
        assert refused[0]["metadata"]["reason"] == "already_linked"
        assert refused[0]["metadata"]["sub"] == "other-sub"


class TestSamlAssignedRefused:
    def test_existing_link_refused(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)
        _assign_saml(test_tenant, test_super_admin_user, test_user)

        with pytest.raises(ForbiddenError) as exc_info:
            svc.authenticate_via_oidc(test_tenant["id"], conn, "subject-123", _claims())
        assert exc_info.value.code == "saml_assigned_user"
        assert _link_row(test_tenant, conn, "subject-123")["last_used_at"] is None

        refused = _events(test_tenant, "oidc_login_refused", test_user["id"])
        assert len(refused) == 1
        assert refused[0]["metadata"]["reason"] == "saml_assigned_user"
        assert refused[0]["metadata"]["idp_id"] == str(conn["id"])
        assert _events(test_tenant, "oidc_login_completed", test_user["id"]) == []

    def test_email_link_refused_and_not_linked(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user, allow_email_linking=True)
        _assign_saml(test_tenant, test_super_admin_user, test_user)

        with pytest.raises(ForbiddenError) as exc_info:
            svc.authenticate_via_oidc(
                test_tenant["id"], conn, "subject-123", _claims(email=test_user["email"])
            )
        assert exc_info.value.code == "saml_assigned_user"
        assert _link_row(test_tenant, conn, "subject-123") is None
        assert len(_events(test_tenant, "oidc_login_refused", test_user["id"])) == 1


class TestEmailLinkingTrustRule:
    def test_untrusted_provider_never_email_links(
        self, test_tenant, test_super_admin_user, test_user
    ):
        """A stored allow_email_linking=true on an untrusted provider is ignored."""
        from services import oidc_upstream as svc

        conn = _make_connection(
            test_tenant,
            test_super_admin_user,
            provider_type="microsoft",
            allow_email_linking=True,
        )
        with pytest.raises(NotFoundError):
            svc.authenticate_via_oidc(
                test_tenant["id"], conn, "msa-sub", _claims(email=test_user["email"])
            )
        assert _link_row(test_tenant, conn, "msa-sub") is None

    def test_unknown_provider_type_fails_closed(self):
        from services.oidc_upstream.presets import email_linking_trusted

        assert email_linking_trusted("discord") is False
        assert email_linking_trusted("nonexistent") is False

    @pytest.mark.parametrize(
        ("provider_type", "trusted"),
        [
            ("generic", True),
            ("google", True),
            ("entra", True),
            ("linkedin", True),
            ("gitlab", True),
            ("microsoft", False),
        ],
    )
    def test_preset_trust(self, provider_type, trusted):
        from services.oidc_upstream.presets import email_linking_trusted, get_preset_defaults

        assert email_linking_trusted(provider_type) is trusted
        assert get_preset_defaults(provider_type)["email_linking_trusted"] is trusted

    def test_create_rejects_email_linking_for_untrusted(self, test_tenant, test_super_admin_user):
        from schemas.oidc_upstream import OIDCConnectionCreate
        from services import oidc_upstream as svc

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with pytest.raises(ValidationError) as exc_info:
            svc.create_connection(
                requesting,
                OIDCConnectionCreate(
                    name="MSA", provider_type="microsoft", allow_email_linking=True
                ),
                "https://t.example.com",
            )
        assert exc_info.value.code == "oidc_email_linking_not_supported"

    def test_create_untrusted_without_email_linking(self, test_tenant, test_super_admin_user):
        from schemas.oidc_upstream import OIDCConnectionCreate
        from services import oidc_upstream as svc

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        config = svc.create_connection(
            requesting,
            OIDCConnectionCreate(name="MSA", provider_type="microsoft"),
            "https://t.example.com",
        )
        assert config.email_linking_trusted is False
        assert config.allow_email_linking is False

    def test_update_rejects_email_linking_for_untrusted(self, test_tenant, test_super_admin_user):
        from schemas.oidc_upstream import OIDCConnectionUpdate
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user, provider_type="microsoft")
        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with pytest.raises(ValidationError) as exc_info:
            svc.update_connection(
                requesting,
                str(conn["id"]),
                OIDCConnectionUpdate(allow_email_linking=True),
                "https://t.example.com",
            )
        assert exc_info.value.code == "oidc_email_linking_not_supported"

        # Turning it off (what the settings form sends) is fine.
        config = svc.update_connection(
            requesting,
            str(conn["id"]),
            OIDCConnectionUpdate(allow_email_linking=False),
            "https://t.example.com",
        )
        assert config.allow_email_linking is False

    def test_trusted_config_flag(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        config = svc.get_connection(requesting, str(conn["id"]), "https://t.example.com")
        assert config.email_linking_trusted is True


# =============================================================================
# Admin: list a user's links
# =============================================================================


class TestListUserLinks:
    def test_lists_links_most_recent_first(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        a = _make_connection(test_tenant, test_super_admin_user, name="A", is_enabled=True)
        b = _make_connection(
            test_tenant,
            test_super_admin_user,
            name="B",
            provider_type="linkedin",
            issuer="https://www.linkedin.com/oauth",
        )
        _link(test_tenant, a, test_user, sub="a-sub")
        _link(test_tenant, b, test_user, sub="b-sub")
        _set_last_used(test_tenant, b, "b-sub", "1 minute")

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        result = svc.list_user_links(requesting, str(test_user["id"]))

        assert [i.connection_name for i in result.items] == ["B", "A"]
        first, second = result.items
        assert first.connection_id == str(b["id"])
        assert first.provider_type == "linkedin"
        assert first.provider_label == "LinkedIn"
        assert first.connection_enabled is False
        assert first.sub == "b-sub"
        assert first.last_used_at is not None
        assert second.connection_enabled is True
        assert second.last_used_at is None

    def test_no_links(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        assert svc.list_user_links(requesting, str(test_user["id"])).items == []

    def test_tracks_activity(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with patch("services.oidc_upstream.links.track_activity") as track:
            svc.list_user_links(requesting, str(test_user["id"]))
        track.assert_called_once_with(str(test_tenant["id"]), str(test_super_admin_user["id"]))

    @pytest.mark.parametrize("role", ["admin", "member"])
    def test_requires_super_admin(self, role, test_tenant, test_admin_user, test_user):
        from services import oidc_upstream as svc

        requesting = _requesting(test_admin_user, test_tenant["id"], role)
        with pytest.raises(ForbiddenError):
            svc.list_user_links(requesting, str(test_user["id"]))

    @pytest.mark.parametrize("user_id", ["not-a-uuid", "00000000-0000-4000-8000-000000000000"])
    def test_unknown_user(self, user_id, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with pytest.raises(NotFoundError) as exc_info:
            svc.list_user_links(requesting, user_id)
        assert exc_info.value.code == "user_not_found"

    def test_tenant_isolation(self, test_tenant, test_super_admin_user, test_user, second_tenant):
        """A super admin of another tenant cannot see this tenant's user's links."""
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        other = RequestingUser(
            id=str(uuid4()), tenant_id=str(second_tenant["id"]), role="super_admin"
        )
        with pytest.raises(NotFoundError):
            svc.list_user_links(other, str(test_user["id"]))


# =============================================================================
# Admin: unlink one link
# =============================================================================


class TestUnlinkOneOfSeveral:
    def test_unlink_non_last_keeps_user_active(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services import oidc_upstream as svc

        a = _make_connection(test_tenant, test_super_admin_user, name="A")
        b = _make_connection(test_tenant, test_super_admin_user, name="B")
        _link(test_tenant, a, test_user, sub="a-sub")
        _link(test_tenant, b, test_user, sub="b-sub")

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with patch("services.oidc_upstream.links.end_user_oidc_sessions") as end_oidc:
            svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(a["id"]))

        assert _link_row(test_tenant, a, "a-sub") is None
        assert _link_row(test_tenant, b, "b-sub") is not None
        user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
        assert user["is_inactivated"] is False
        end_oidc.assert_not_called()
        emails = database.user_emails.list_user_emails(test_tenant["id"], str(test_user["id"]))
        assert any(e["verified_at"] is not None for e in emails)

        unlinked = _events(test_tenant, "user_oidc_idp_unlinked", test_user["id"])
        assert len(unlinked) == 1
        assert unlinked[0]["metadata"]["sub"] == "a-sub"
        assert unlinked[0]["metadata"]["remaining_links"] == 1
        assert _events(test_tenant, "user_inactivated", test_user["id"]) == []

    def test_unlink_last_deactivates(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with patch("services.oidc_upstream.links.end_user_oidc_sessions"):
            svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))

        user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
        assert user["is_inactivated"] is True
        unlinked = _events(test_tenant, "user_oidc_idp_unlinked", test_user["id"])
        assert unlinked[0]["metadata"]["remaining_links"] == 0
        inactivated = _events(test_tenant, "user_inactivated", test_user["id"])
        assert inactivated[0]["metadata"]["cause"] == "oidc_disconnect"

    def test_malformed_ids_not_found(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        requesting = _requesting(test_super_admin_user, test_tenant["id"])
        with pytest.raises(NotFoundError) as exc_info:
            svc.unlink_user_from_connection(requesting, "bad", str(uuid4()))
        assert exc_info.value.code == "user_not_found"
        with pytest.raises(NotFoundError) as exc_info:
            svc.unlink_user_from_connection(requesting, str(test_user["id"]), "bad")
        assert exc_info.value.code == "oidc_connection_not_found"
