"""Tests for the sign-in page buttons (show on login) at the data and service layers.

Covers: the login-page connection query, ``list_login_buttons`` (label,
logo, generic name fallback, enabled-only, ordering, tenant isolation),
``show_on_login`` on create/update with its audit trail, the preset button
style, the provider logo template helper, and the ``entry`` field on sign-in
audit events.
"""

from uuid import uuid4

import pytest
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


def _requesting(user, tenant_id):
    return RequestingUser(id=str(user["id"]), tenant_id=str(tenant_id), role="super_admin")


def _make_connection(tenant, created_by, name="Social", **overrides):
    import database

    kwargs = {
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
        "is_enabled": True,
        "show_on_login": True,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=name,
        created_by=str(created_by["id"]),
        **kwargs,
    )


def _events(tenant_id, event_type):
    import database

    return [
        e
        for e in database.event_log.list_events(tenant_id, limit=100)
        if e["event_type"] == event_type
    ]


# =============================================================================
# Database layer
# =============================================================================


class TestLoginPageConnections:
    def test_create_stores_show_on_login(self, test_tenant, test_super_admin_user):
        row = _make_connection(test_tenant, test_super_admin_user)
        assert row["show_on_login"] is True
        off = _make_connection(test_tenant, test_super_admin_user, name="Off", show_on_login=False)
        assert off["show_on_login"] is False

    def test_lists_enabled_shown_connections_by_name(self, test_tenant, test_super_admin_user):
        import database

        _make_connection(test_tenant, test_super_admin_user, name="beta")
        _make_connection(test_tenant, test_super_admin_user, name="Alpha")
        _make_connection(test_tenant, test_super_admin_user, name="Hidden", show_on_login=False)
        _make_connection(test_tenant, test_super_admin_user, name="Disabled", is_enabled=False)

        rows = database.oidc_upstream.list_login_page_connections(test_tenant["id"])
        assert [r["name"] for r in rows] == ["Alpha", "beta"]
        assert set(rows[0]) == {"id", "name", "provider_type"}

    def test_empty_when_none_shown(self, test_tenant, test_super_admin_user):
        import database

        _make_connection(test_tenant, test_super_admin_user, show_on_login=False)
        assert database.oidc_upstream.list_login_page_connections(test_tenant["id"]) == []


# =============================================================================
# Service: list_login_buttons
# =============================================================================


class TestListLoginButtons:
    def test_preset_label_and_logo(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream import list_login_buttons

        conn = _make_connection(
            test_tenant,
            test_super_admin_user,
            name="Our Google",
            provider_type="google",
            issuer="https://accounts.google.com",
        )
        [button] = list_login_buttons(str(test_tenant["id"]))
        assert button.connection_id == str(conn["id"])
        assert button.provider_type == "google"
        assert button.label == "Google"
        assert button.logo == "google"

    def test_entra_shows_as_microsoft(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream import list_login_buttons

        _make_connection(test_tenant, test_super_admin_user, provider_type="entra")
        [button] = list_login_buttons(str(test_tenant["id"]))
        assert (button.label, button.logo) == ("Microsoft", "microsoft")

    def test_generic_uses_connection_name_without_logo(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream import list_login_buttons

        _make_connection(test_tenant, test_super_admin_user, name="Acme Login")
        [button] = list_login_buttons(str(test_tenant["id"]))
        assert button.label == "Acme Login"
        assert button.logo is None

    def test_excludes_hidden_and_disabled(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream import list_login_buttons

        _make_connection(test_tenant, test_super_admin_user, show_on_login=False)
        _make_connection(test_tenant, test_super_admin_user, name="Off", is_enabled=False)
        assert list_login_buttons(str(test_tenant["id"])) == []

    def test_tenant_isolation(self, test_tenant, test_super_admin_user, second_tenant):
        from services.oidc_upstream import list_login_buttons

        _make_connection(test_tenant, test_super_admin_user)
        assert list_login_buttons(str(second_tenant["id"])) == []


# =============================================================================
# Service: show_on_login on create / update
# =============================================================================


class TestShowOnLoginSetting:
    def test_create_sets_flag_and_logs_it(self, test_tenant, test_super_admin_user):
        from schemas.oidc_upstream import OIDCConnectionCreate
        from services.oidc_upstream import create_connection

        config = create_connection(
            _requesting(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(
                name="Button",
                provider_type="google",
                client_id="cid",
                show_on_login=True,
            ),
            "https://t.example.com",
        )
        assert config.show_on_login is True
        event = next(
            e
            for e in _events(test_tenant["id"], "oidc_idp_connection_created")
            if str(e["artifact_id"]) == config.id
        )
        assert event["metadata"]["show_on_login"] is True

    def test_create_defaults_off(self, test_tenant, test_super_admin_user):
        from schemas.oidc_upstream import OIDCConnectionCreate
        from services.oidc_upstream import create_connection

        config = create_connection(
            _requesting(test_super_admin_user, test_tenant["id"]),
            OIDCConnectionCreate(name="No button", provider_type="google"),
            "https://t.example.com",
        )
        assert config.show_on_login is False

    def test_update_toggles_flag_and_logs_it(self, test_tenant, test_super_admin_user):
        from schemas.oidc_upstream import OIDCConnectionUpdate
        from services.oidc_upstream import list_connections, update_connection

        conn = _make_connection(test_tenant, test_super_admin_user, show_on_login=False)
        requesting = _requesting(test_super_admin_user, test_tenant["id"])

        config = update_connection(
            requesting,
            str(conn["id"]),
            OIDCConnectionUpdate(show_on_login=True),
            "https://t.example.com",
        )
        assert config.show_on_login is True
        [event] = [
            e
            for e in _events(test_tenant["id"], "oidc_idp_connection_updated")
            if str(e["artifact_id"]) == str(conn["id"])
        ]
        assert event["metadata"]["updated_fields"] == ["show_on_login"]
        assert list_connections(requesting).items[0].show_on_login is True

        config = update_connection(
            requesting,
            str(conn["id"]),
            OIDCConnectionUpdate(show_on_login=False),
            "https://t.example.com",
        )
        assert config.show_on_login is False


# =============================================================================
# Presets and logos
# =============================================================================


class TestButtonStyle:
    @pytest.mark.parametrize(
        ("provider_type", "expected"),
        [
            ("generic", (None, None)),
            ("google", ("Google", "google")),
            ("entra", ("Microsoft", "microsoft")),
            ("microsoft", ("Microsoft", "microsoft")),
            ("linkedin", ("LinkedIn", "linkedin")),
            ("gitlab", ("GitLab", "gitlab")),
            ("unknown", (None, None)),
        ],
    )
    def test_login_button_style(self, provider_type, expected):
        from services.oidc_upstream.presets import login_button_style

        assert login_button_style(provider_type) == expected

    def test_every_preset_logo_has_a_file(self):
        from services.oidc_upstream.presets import _PRESETS
        from utils.templates import _PROVIDER_LOGOS_DIR

        for preset in _PRESETS.values():
            if preset.logo:
                assert (_PROVIDER_LOGOS_DIR / f"{preset.logo}.svg").is_file(), preset.logo


class TestProviderLogoHelper:
    def test_renders_svg_with_attributes(self):
        from utils.templates import provider_logo

        html = str(provider_logo("google", **{"class": "w-5 h-5"}))
        assert html.startswith('<svg class="w-5 h-5"')
        assert "#4285F4" in html

    @pytest.mark.parametrize("name", [None, "", "no-such-provider", "../icons/link", "Google"])
    def test_missing_or_unsafe_name_renders_nothing(self, name):
        from utils.templates import provider_logo

        assert str(provider_logo(name)) == ""


# =============================================================================
# Sign-in audit events carry the entry point
# =============================================================================


class TestEntryOnSignInEvents:
    def _claims(self, **overrides):
        claims = {
            "sub": "subject-123",
            "email": "button-user@example.com",
            "email_verified": True,
            "given_name": "Button",
            "family_name": "User",
        }
        claims.update(overrides)
        return claims

    def test_existing_link_records_entry(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services.oidc_upstream import ENTRY_LOGIN_BUTTON, authenticate_via_oidc

        conn = _make_connection(test_tenant, test_super_admin_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        authenticate_via_oidc(
            str(test_tenant["id"]), conn, "subject-123", self._claims(), entry=ENTRY_LOGIN_BUTTON
        )
        [event] = _events(test_tenant["id"], "oidc_login_completed")
        assert event["metadata"]["entry"] == "login_button"

    def test_entry_defaults_to_routed(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services.oidc_upstream import authenticate_via_oidc

        conn = _make_connection(test_tenant, test_super_admin_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        authenticate_via_oidc(str(test_tenant["id"]), conn, "subject-123", self._claims())
        [event] = _events(test_tenant["id"], "oidc_login_completed")
        assert event["metadata"]["entry"] == "routed"

    def test_jit_sign_in_records_entry(self, test_tenant, test_super_admin_user):
        from services.oidc_upstream import ENTRY_LOGIN_BUTTON, authenticate_via_oidc

        conn = _make_connection(test_tenant, test_super_admin_user, jit_provisioning=True)
        user = authenticate_via_oidc(
            str(test_tenant["id"]), conn, "subject-123", self._claims(), entry=ENTRY_LOGIN_BUTTON
        )
        [event] = _events(test_tenant["id"], "oidc_user_jit_provisioned")
        assert str(event["artifact_id"]) == str(user["id"])
        assert event["metadata"]["entry"] == "login_button"
        # A JIT sign-in is recorded by the provisioning event alone.
        assert _events(test_tenant["id"], "oidc_login_completed") == []

    def test_refusal_records_entry(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services.exceptions import ForbiddenError
        from services.oidc_upstream import ENTRY_LOGIN_BUTTON, authenticate_via_oidc

        conn = _make_connection(test_tenant, test_super_admin_user)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        idp = database.saml.create_identity_provider(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Corp SAML",
            provider_type="okta",
            sp_entity_id=f"https://sp.example.com/{uuid4()}",
            created_by=str(test_super_admin_user["id"]),
            is_enabled=True,
        )
        database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), str(idp["id"]))

        with pytest.raises(ForbiddenError):
            authenticate_via_oidc(
                str(test_tenant["id"]),
                conn,
                "subject-123",
                self._claims(),
                entry=ENTRY_LOGIN_BUTTON,
            )
        [event] = _events(test_tenant["id"], "oidc_login_refused")
        assert event["metadata"]["entry"] == "login_button"
