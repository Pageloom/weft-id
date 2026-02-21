"""Basic happy path tests for OAuth2 flows and API endpoints."""


def test_client_credentials_flow(client, test_tenant_host, b2b_oauth2_client):
    """Test OAuth2 client credentials flow (B2B)."""
    # Request access token using client credentials
    response = client.post(
        "/oauth2/token",
        headers={"Host": test_tenant_host},
        data={
            "grant_type": "client_credentials",
            "client_id": b2b_oauth2_client["client_id"],
            "client_secret": b2b_oauth2_client["client_secret"],
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 86400  # 24 hours
    assert data.get("refresh_token") is None  # No refresh token for client credentials


def test_api_with_bearer_token(client, test_tenant_host, oauth2_authorization_header):
    """Test API endpoint with Bearer token authentication."""
    response = client.get(
        "/api/v1/users/me",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()

    assert "id" in data
    assert "email" in data
    assert "first_name" in data
    assert "role" in data


def test_oauth2_client_management_create_normal(
    client, test_tenant_host, test_admin_user, oauth2_admin_authorization_header
):
    """Test creating a normal OAuth2 client via API."""
    # Use Bearer token authentication (admin access token)
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "name": "Test API Client",
            "redirect_uris": ["http://localhost:3000/callback"],
        },
    )

    assert response.status_code == 201
    data = response.json()

    assert "client_id" in data
    assert "client_secret" in data
    assert data["name"] == "Test API Client"
    assert data["client_type"] == "normal"


def test_oauth2_client_management_list(
    client, test_tenant_host, normal_oauth2_client, oauth2_admin_authorization_header
):
    """Test listing OAuth2 clients via API with Bearer token."""
    response = client.get(
        "/api/v1/oauth2/clients",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # Should have at least the client we created
    assert len(data) >= 1


def test_openapi_spec_available(client, test_host):
    """Test that OpenAPI spec is available at /openapi.json."""
    response = client.get(
        "/openapi.json",
        headers={"Host": test_host},
    )

    assert response.status_code == 200
    data = response.json()

    assert "openapi" in data
    assert "paths" in data
    assert "components" in data

    # Check that security schemes are defined
    security_schemes = data["components"].get("securitySchemes", {})
    assert "BearerToken" in security_schemes
    assert "SessionCookie" in security_schemes


def test_token_validation_with_invalid_token(client, test_tenant_host):
    """Test API endpoint with invalid Bearer token."""
    response = client.get(
        "/api/v1/users/me",
        headers={
            "Authorization": "Bearer invalid_token_123",
            "Host": test_tenant_host,
        },
    )

    assert response.status_code == 401
