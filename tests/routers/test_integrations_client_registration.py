"""Admin web UI for dynamic client registration
(/applications/client-registration): policy and default access, initial
access tokens, and the Registered badge on registered apps. Real database;
auth via override_auth."""

import database
import pytest
from main import app
from schemas.oauth2 import InitialAccessTokenCreate, RegistrationSettingsUpdate
from services import oauth2_registration as registration_service
from services.exceptions import UnauthorizedError

from tests.helpers.client import TestClient

PAGE = "/applications/client-registration"


def _admin(test_admin_user):
    return {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_admin_user["tenant_id"]),
        "role": "admin",
    }


def _client_for(override_auth, user, level="admin"):
    override_auth(user, level=level)
    return TestClient(app)


class TestPage:
    def test_renders_defaults(self, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        page = client.get(PAGE)

        assert page.status_code == 200
        assert "Client Registration" in page.text
        assert 'value="off" class="mt-1" checked' in page.text
        assert 'value="none" class="mt-1" checked' in page.text
        assert "/oauth2/register" in page.text
        assert "No initial access tokens." in page.text

    def test_member_redirected(self, test_user, override_auth):
        client = _client_for(override_auth, test_user)

        response = client.get(PAGE, follow_redirects=False)

        assert response.headers["location"] == "/dashboard"

    def test_lists_tokens(self, test_admin_user, override_auth):
        registration_service.create_initial_access_token(
            _admin(test_admin_user), InitialAccessTokenCreate(name="Partner onboarding")
        )
        client = _client_for(override_auth, test_admin_user)

        page = client.get(PAGE).text

        assert "Partner onboarding" in page
        assert "Revoke" in page
        assert "weft-id_iat_" not in page


class TestSettings:
    def test_save(self, test_tenant, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        response = client.post(
            f"{PAGE}/settings",
            data={"policy": "token_required", "default_access": "all"},
            follow_redirects=False,
        )

        assert response.headers["location"] == f"{PAGE}?success=settings_saved"
        row = database.oauth2.get_registration_settings(test_tenant["id"])
        assert (row["policy"], row["default_access"]) == ("token_required", "all")
        assert "Registration settings saved." in client.get(response.headers["location"]).text

    def test_invalid_value(self, test_tenant, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        response = client.post(
            f"{PAGE}/settings",
            data={"policy": "always", "default_access": "none"},
            follow_redirects=False,
        )

        assert response.headers["location"] == f"{PAGE}?error=invalid_settings"
        assert database.oauth2.get_registration_settings(test_tenant["id"]) is None

    def test_member_redirected(self, test_tenant, test_user, override_auth):
        client = _client_for(override_auth, test_user)

        response = client.post(
            f"{PAGE}/settings",
            data={"policy": "open", "default_access": "all"},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/dashboard"
        assert database.oauth2.get_registration_settings(test_tenant["id"]) is None


class TestTokens:
    def test_create_shows_value_once(self, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        response = client.post(
            f"{PAGE}/tokens",
            data={"name": "Partner", "expires_in_days": "30"},
            follow_redirects=False,
        )
        first = client.get(response.headers["location"]).text
        second = client.get(PAGE).text

        assert response.headers["location"] == f"{PAGE}?success=token_created"
        assert "weft-id_iat_" in first
        assert "pending-token-modal" in first
        assert "weft-id_iat_" not in second
        assert "Partner" in second

    def test_no_expiry(self, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        client.post(f"{PAGE}/tokens", data={"name": "Forever", "expires_in_days": ""})

        tokens = registration_service.list_initial_access_tokens(_admin(test_admin_user))
        assert tokens[0].expires_at is None

    def test_name_required(self, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        response = client.post(f"{PAGE}/tokens", data={"name": "  "}, follow_redirects=False)

        assert response.headers["location"] == f"{PAGE}?error=name_required"

    def test_invalid_expiry(self, test_admin_user, override_auth):
        client = _client_for(override_auth, test_admin_user)

        for value in ("abc", "0", "366"):
            response = client.post(
                f"{PAGE}/tokens",
                data={"name": "T", "expires_in_days": value},
                follow_redirects=False,
            )
            assert response.headers["location"] == f"{PAGE}?error=invalid_expiry"
        assert registration_service.list_initial_access_tokens(_admin(test_admin_user)) == []

    def test_revoke(self, test_admin_user, override_auth):
        token = registration_service.create_initial_access_token(
            _admin(test_admin_user), InitialAccessTokenCreate(name="T")
        )
        client = _client_for(override_auth, test_admin_user)

        response = client.post(f"{PAGE}/tokens/{token.id}/revoke", follow_redirects=False)
        again = client.post(f"{PAGE}/tokens/{token.id}/revoke", follow_redirects=False)

        assert response.headers["location"] == f"{PAGE}?success=token_revoked"
        assert again.headers["location"] == f"{PAGE}?error=token_not_found"
        tokens = registration_service.list_initial_access_tokens(_admin(test_admin_user))
        assert tokens[0].status == "revoked"

    def test_member_cannot_create_or_revoke(self, test_admin_user, test_user, override_auth):
        token = registration_service.create_initial_access_token(
            _admin(test_admin_user), InitialAccessTokenCreate(name="T")
        )
        client = _client_for(override_auth, test_user)

        create = client.post(f"{PAGE}/tokens", data={"name": "X"}, follow_redirects=False)
        revoke = client.post(f"{PAGE}/tokens/{token.id}/revoke", follow_redirects=False)

        assert create.headers["location"] == "/dashboard"
        assert revoke.headers["location"] == "/dashboard"
        tokens = registration_service.list_initial_access_tokens(_admin(test_admin_user))
        assert [t.status for t in tokens] == ["active"]


class TestRegisteredBadge:
    def test_list_and_detail(
        self, test_tenant, test_admin_user, override_auth, normal_oauth2_client
    ):
        registration_service.update_registration_settings(
            _admin(test_admin_user),
            RegistrationSettingsUpdate(policy="open"),
            "https://unused.example",
        )
        body = registration_service.register_client(
            test_tenant["id"],
            {
                "redirect_uris": ["https://rp.example/cb"],
                "client_name": "Self Registered",
                "policy_uri": "https://rp.example/privacy",
            },
            initial_access_token=None,
            base_url="https://unused.example",
        )
        client = _client_for(override_auth, test_admin_user)

        listing = client.get("/applications/oauth").text
        detail = client.get(f"/applications/oauth/{body['client_id']}").text
        static_detail = client.get(f"/applications/oauth/{normal_oauth2_client['client_id']}").text

        assert "Self Registered" in listing
        assert ">Registered</span>" in listing
        assert "registered itself through" in detail
        assert "https://rp.example/privacy" in detail
        assert "registered itself through" not in static_detail


def _register_open(test_tenant, test_admin_user):
    registration_service.update_registration_settings(
        _admin(test_admin_user),
        RegistrationSettingsUpdate(policy="open"),
        "https://unused.example",
    )
    return registration_service.register_client(
        test_tenant["id"],
        {"redirect_uris": ["https://rp.example/cb"], "client_name": "Self Registered"},
        initial_access_token=None,
        base_url="https://unused.example",
    )


class TestResetRegistrationToken:
    def test_reset_shows_the_new_token_once(self, test_tenant, test_admin_user, override_auth):
        body = _register_open(test_tenant, test_admin_user)
        client = _client_for(override_auth, test_admin_user)
        detail_url = f"/applications/oauth/{body['client_id']}"

        assert "Reset Registration Access Token" in client.get(detail_url).text
        response = client.post(f"{detail_url}/reset-registration-token", follow_redirects=False)

        assert response.headers["location"] == f"{detail_url}?success=registration_token_reset"
        first = client.get(response.headers["location"]).text
        assert "New Registration Access Token" in first
        assert "weft-id_rat" in first
        second = client.get(response.headers["location"]).text
        assert "New Registration Access Token" not in second
        assert "Registration access token reset." in second
        # The client's old token no longer opens its configuration.
        with pytest.raises(UnauthorizedError):
            registration_service.authenticate_registration(
                test_tenant["id"], body["client_id"], body["registration_access_token"]
            )

    def test_not_offered_for_admin_created_app(
        self, test_admin_user, override_auth, normal_oauth2_client
    ):
        client = _client_for(override_auth, test_admin_user)
        detail_url = f"/applications/oauth/{normal_oauth2_client['client_id']}"

        assert "Reset Registration Access Token" not in client.get(detail_url).text
        response = client.post(f"{detail_url}/reset-registration-token", follow_redirects=False)
        assert response.headers["location"] == (
            f"{detail_url}?error=registration_token_reset_failed"
        )

    def test_member_redirected(self, test_tenant, test_admin_user, test_user, override_auth):
        body = _register_open(test_tenant, test_admin_user)
        client = _client_for(override_auth, test_user)

        response = client.post(
            f"/applications/oauth/{body['client_id']}/reset-registration-token",
            follow_redirects=False,
        )

        assert response.headers["location"] == "/dashboard"
        registration_service.authenticate_registration(
            test_tenant["id"], body["client_id"], body["registration_access_token"]
        )
