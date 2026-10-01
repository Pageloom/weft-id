"""API tests: PUT /api/v1/oauth2/clients/{client_id}/authentication and the
authentication fields on client responses."""

import database
import oauth2

from tests.helpers.client_keys import JWKS

URI = "https://keys.example.com/jwks.json"


def _put(client, host, headers, client_id, body):
    return client.put(
        f"/api/v1/oauth2/clients/{client_id}/authentication",
        headers={"Host": host, **headers},
        json=body,
    )


def test_client_response_has_authentication_fields(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    data = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    ).json()
    assert data["client_auth_method"] == "client_secret"
    assert data["jwks"] is None
    assert data["jwks_uri"] is None
    assert data["token_endpoint_auth_signing_alg"] is None


def test_switch_to_private_key_jwt(
    client, test_tenant, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client["client_id"],
        {"method": "private_key_jwt", "jwks": JWKS},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["client_auth_method"] == "private_key_jwt"
    assert data["jwks"] == JWKS
    assert data["client_secret"] is None
    events = [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "oauth2_client_authentication_changed"
    ]
    assert len(events) == 1


def test_switch_back_returns_secret_once(
    client, test_tenant, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    client_id = normal_oauth2_client["client_id"]
    headers = oauth2_admin_authorization_header
    _put(
        client, test_tenant_host, headers, client_id, {"method": "private_key_jwt", "jwks_uri": URI}
    )

    data = _put(client, test_tenant_host, headers, client_id, {"method": "client_secret"}).json()

    assert data["client_auth_method"] == "client_secret"
    row = database.oauth2.get_client_by_client_id(test_tenant["id"], client_id)
    assert oauth2.verify_token_hash(data["client_secret"], row["client_secret_hash"])
    again = client.get(
        f"/api/v1/oauth2/clients/{client_id}", headers={"Host": test_tenant_host, **headers}
    ).json()
    assert "client_secret" not in again


def test_validation_errors_are_400(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    for body in (
        {"method": "private_key_jwt"},
        {"method": "private_key_jwt", "jwks": JWKS, "jwks_uri": URI},
        {"method": "private_key_jwt", "jwks": {"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}},
        {"method": "private_key_jwt", "jwks_uri": "http://keys.example.com/jwks"},
    ):
        response = _put(
            client,
            test_tenant_host,
            oauth2_admin_authorization_header,
            normal_oauth2_client["client_id"],
            body,
        )
        assert response.status_code == 400, (body, response.text)


def test_schema_errors_are_422(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    for body in (
        {"method": "tls_client_auth"},
        {"method": "client_secret", "jwks_uri": "a" * 2049},
    ):
        response = _put(
            client,
            test_tenant_host,
            oauth2_admin_authorization_header,
            normal_oauth2_client["client_id"],
            body,
        )
        assert response.status_code == 422


def test_unknown_client_404(client, test_tenant_host, oauth2_admin_authorization_header):
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        "weft-id_client_nope",
        {"method": "client_secret"},
    )
    assert response.status_code == 404


def test_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = _put(
        client,
        test_tenant_host,
        oauth2_authorization_header,
        normal_oauth2_client["client_id"],
        {"method": "private_key_jwt", "jwks": JWKS},
    )
    assert response.status_code == 403


def test_b2b_needs_super_admin(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    oauth2_super_admin_authorization_header,
    b2b_oauth2_client,
):
    body = {"method": "private_key_jwt", "jwks": JWKS}
    client_id = b2b_oauth2_client["client_id"]
    admin = _put(client, test_tenant_host, oauth2_admin_authorization_header, client_id, body)
    assert admin.status_code == 403
    super_admin = _put(
        client, test_tenant_host, oauth2_super_admin_authorization_header, client_id, body
    )
    assert super_admin.status_code == 200
    assert super_admin.json()["client_auth_method"] == "private_key_jwt"


def test_regenerate_refused_for_private_key_jwt(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    client_id = normal_oauth2_client["client_id"]
    headers = oauth2_admin_authorization_header
    _put(client, test_tenant_host, headers, client_id, {"method": "private_key_jwt", "jwks": JWKS})
    response = client.post(
        f"/api/v1/oauth2/clients/{client_id}/regenerate-secret",
        headers={"Host": test_tenant_host, **headers},
    )
    assert response.status_code == 400
