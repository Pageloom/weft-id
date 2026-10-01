"""API tests: PUT /api/v1/oauth2/clients/{client_id}/subject and the subject
fields on client responses."""

import database
import httpx
from services.oidc import subject as subject_service

SECTOR = "https://sector.example/redirect_uris.json"


def _put(client, host, headers, client_id, body):
    return client.put(
        f"/api/v1/oauth2/clients/{client_id}/subject",
        headers={"Host": host, **headers},
        json=body,
    )


def _serve(monkeypatch, document):
    monkeypatch.setattr(
        subject_service,
        "build_safe_client",
        lambda **_: httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=document))
        ),
    )


def test_client_response_has_subject_fields(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    data = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    ).json()
    assert data["subject_type"] == "public"
    assert data["sector_identifier_uri"] is None


def test_switch_to_pairwise(
    client, test_tenant, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client["client_id"],
        {"subject_type": "pairwise"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["subject_type"] == "pairwise"
    events = [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "oauth2_client_subject_type_changed"
    ]
    assert len(events) == 1


def test_sector_identifier_uri(
    monkeypatch,
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    _serve(monkeypatch, normal_oauth2_client["redirect_uris"])
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client["client_id"],
        {"subject_type": "pairwise", "sector_identifier_uri": SECTOR},
    )
    assert response.status_code == 200, response.text
    assert response.json()["sector_identifier_uri"] == SECTOR


def test_sector_document_missing_redirect_is_400(
    monkeypatch,
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    _serve(monkeypatch, ["https://example.com/op"])
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client["client_id"],
        {"subject_type": "pairwise", "sector_identifier_uri": SECTOR},
    )
    assert response.status_code == 400


def test_unknown_subject_type_is_422(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client["client_id"],
        {"subject_type": "pseudonymous"},
    )
    assert response.status_code == 422


def test_b2b_client_is_404(
    client, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
):
    response = _put(
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        b2b_oauth2_client["client_id"],
        {"subject_type": "pairwise"},
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
        {"subject_type": "pairwise"},
    )
    assert response.status_code == 403
