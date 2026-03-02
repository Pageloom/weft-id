"""Tests for the /healthz health check endpoint."""

from unittest.mock import patch

from fastapi.testclient import TestClient


class TestHealthCheck:
    """Tests for GET /healthz."""

    def test_healthz_returns_200_when_db_reachable(self, client: TestClient):
        """Health check returns 200 with empty body when database is reachable."""
        response = client.get("/healthz")

        assert response.status_code == 200
        assert response.content == b""

    def test_healthz_returns_503_when_db_unreachable(self, client: TestClient):
        """Health check returns 503 when database query fails."""
        with patch(
            "services.health.database.fetchone",
            side_effect=Exception("connection refused"),
        ):
            response = client.get("/healthz")

        assert response.status_code == 503
        assert response.content == b""

    def test_healthz_no_tenant_required(self, client: TestClient):
        """Health check works without a tenant subdomain (no Host header matching)."""
        # TestClient sends Host: testserver by default, which has no subdomain.
        # The endpoint should still work because it doesn't depend on tenant resolution.
        response = client.get("/healthz")

        assert response.status_code == 200

    def test_healthz_with_bare_domain_host(self, client: TestClient):
        """Health check works even when Host is the bare domain (exempt from tenant guard)."""
        import settings

        response = client.get("/healthz", headers={"host": settings.BASE_DOMAIN})

        assert response.status_code == 200
