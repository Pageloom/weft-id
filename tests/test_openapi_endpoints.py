"""Tests for OpenAPI/Swagger documentation endpoints."""


def test_docs_endpoint_accessible_when_enabled(client, test_tenant_host):
    """Test that /api/docs is accessible when ENABLE_OPENAPI_DOCS=True."""
    # Current test environment has ENABLE_OPENAPI_DOCS=true in .env
    response = client.get("/api/docs", headers={"Host": test_tenant_host})

    # Should return 200 (Swagger UI HTML)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_redoc_endpoint_accessible_when_enabled(client, test_tenant_host):
    """Test that /api/redoc is accessible when ENABLE_OPENAPI_DOCS=True."""
    response = client.get("/api/redoc", headers={"Host": test_tenant_host})

    # Should return 200 (ReDoc UI HTML)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_openapi_json_accessible_when_enabled(client, test_tenant_host):
    """Test that /openapi.json returns valid schema when ENABLE_OPENAPI_DOCS=True."""
    response = client.get("/openapi.json", headers={"Host": test_tenant_host})

    # Should return 200 with JSON schema
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")

    data = response.json()

    # Verify it's a valid OpenAPI schema
    assert "openapi" in data
    assert "info" in data
    assert data["info"]["title"] == "Loom Identity Platform API"
    assert "paths" in data
