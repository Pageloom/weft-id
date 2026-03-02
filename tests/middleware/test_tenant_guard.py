"""Tests for the TenantGuardMiddleware (bare domain rejection)."""

from unittest.mock import patch

from fastapi.testclient import TestClient


class TestTenantGuardMiddleware:
    """Tests for bare domain and www rejection."""

    def test_bare_domain_returns_400(self, client: TestClient):
        """Requests to the bare domain are rejected with 400."""
        import settings

        response = client.get("/login", headers={"host": settings.BASE_DOMAIN})

        assert response.status_code == 400
        assert "Tenant subdomain required" in response.text

    def test_www_subdomain_returns_400(self, client: TestClient):
        """Requests to www.BASE_DOMAIN are rejected with 400."""
        import settings

        response = client.get("/login", headers={"host": f"www.{settings.BASE_DOMAIN}"})

        assert response.status_code == 400
        assert "Tenant subdomain required" in response.text

    def test_valid_subdomain_passes_through(self, client: TestClient):
        """Requests with a valid tenant subdomain are not blocked by the guard."""
        import settings

        # This will pass the guard but may fail later (e.g., unknown tenant).
        # We just verify the guard doesn't return 400.
        response = client.get("/login", headers={"host": f"dev.{settings.BASE_DOMAIN}"})

        assert response.status_code != 400

    def test_healthz_exempt_on_bare_domain(self, client: TestClient):
        """The /healthz endpoint is exempt from the tenant guard."""
        import settings

        response = client.get("/healthz", headers={"host": settings.BASE_DOMAIN})

        assert response.status_code == 200

    def test_healthz_exempt_on_www(self, client: TestClient):
        """The /healthz endpoint is exempt from the tenant guard even on www."""
        import settings

        response = client.get("/healthz", headers={"host": f"www.{settings.BASE_DOMAIN}"})

        assert response.status_code == 200

    def test_bare_domain_with_port_returns_400(self, client: TestClient):
        """Bare domain with port number is still rejected."""
        import settings

        response = client.get("/login", headers={"host": f"{settings.BASE_DOMAIN}:8080"})

        assert response.status_code == 400

    def test_bare_domain_case_insensitive(self, client: TestClient):
        """Host header matching is case-insensitive."""
        import settings

        response = client.get("/login", headers={"host": settings.BASE_DOMAIN.upper()})

        assert response.status_code == 400

    def test_x_forwarded_host_bare_domain_returns_400(self, client: TestClient):
        """Bare domain via X-Forwarded-Host header is also rejected."""
        import settings

        response = client.get(
            "/login",
            headers={
                "host": "anything.internal",
                "x-forwarded-host": settings.BASE_DOMAIN,
            },
        )

        assert response.status_code == 400

    def test_guard_skipped_when_base_domain_empty(self, client: TestClient):
        """Guard is a no-op when BASE_DOMAIN is not configured."""
        with patch("middleware.tenant_guard.settings.BASE_DOMAIN", ""):
            # Should pass through the guard (won't reject anything)
            response = client.get("/healthz")

        assert response.status_code == 200

    def test_error_page_is_valid_html(self, client: TestClient):
        """The 400 error page is self-contained HTML with no template dependencies."""
        import settings

        response = client.get("/login", headers={"host": settings.BASE_DOMAIN})

        assert response.status_code == 400
        assert "<!DOCTYPE html>" in response.text
        assert "<html" in response.text
        assert "yourcompany.weft.id" in response.text
