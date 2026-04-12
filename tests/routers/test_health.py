"""Tests for infrastructure endpoints: /healthz and /caddy/check-domain."""

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


class TestCheckDomain:
    """Tests for GET /caddy/check-domain."""

    def test_known_tenant_subdomain_returns_200(self, client: TestClient, test_tenant):
        """Valid tenant subdomain returns 200 (allow certificate issuance)."""
        import settings

        domain = f"{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"
        response = client.get("/caddy/check-domain", params={"domain": domain})

        assert response.status_code == 200

    def test_unknown_subdomain_returns_404(self, client: TestClient):
        """Unknown subdomain returns 404 (deny certificate issuance)."""
        import settings

        domain = f"nonexistent-tenant-xyz.{settings.BASE_DOMAIN}"
        response = client.get("/caddy/check-domain", params={"domain": domain})

        assert response.status_code == 404

    def test_bare_base_domain_returns_200(self, client: TestClient):
        """Bare base domain returns 200 (it needs a certificate too)."""
        import settings

        response = client.get("/caddy/check-domain", params={"domain": settings.BASE_DOMAIN})

        assert response.status_code == 200

    def test_unrelated_domain_returns_404(self, client: TestClient):
        """Domain that is not a subdomain of BASE_DOMAIN returns 404."""
        response = client.get("/caddy/check-domain", params={"domain": "evil.example.com"})

        assert response.status_code == 404

    def test_missing_domain_param_returns_400(self, client: TestClient):
        """Missing domain parameter returns 400."""
        response = client.get("/caddy/check-domain")

        assert response.status_code == 400

    def test_empty_domain_param_returns_400(self, client: TestClient):
        """Empty domain parameter returns 400."""
        response = client.get("/caddy/check-domain", params={"domain": ""})

        assert response.status_code == 400

    def test_multi_level_subdomain_returns_404(self, client: TestClient, test_tenant):
        """Multi-level subdomain returns 404 even if the leaf matches a tenant."""
        import settings

        domain = f"extra.{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"
        response = client.get("/caddy/check-domain", params={"domain": domain})

        assert response.status_code == 404

    def test_domain_normalized_case_insensitive(self, client: TestClient, test_tenant):
        """Domain matching is case-insensitive."""
        import settings

        domain = f"{test_tenant['subdomain'].upper()}.{settings.BASE_DOMAIN.upper()}"
        response = client.get("/caddy/check-domain", params={"domain": domain})

        assert response.status_code == 200

    def test_domain_trailing_dot_stripped(self, client: TestClient, test_tenant):
        """Trailing dot in FQDN is stripped before matching."""
        import settings

        domain = f"{test_tenant['subdomain']}.{settings.BASE_DOMAIN}."
        response = client.get("/caddy/check-domain", params={"domain": domain})

        assert response.status_code == 200

    def test_no_base_domain_configured_allows_all(self, client: TestClient):
        """When BASE_DOMAIN is empty, all domains are allowed (dev environment)."""
        with patch("routers.health.settings") as mock_settings:
            mock_settings.BASE_DOMAIN = ""
            response = client.get("/caddy/check-domain", params={"domain": "anything.example.com"})

        assert response.status_code == 200

    def test_exempt_from_tenant_guard(self, client: TestClient):
        """Endpoint works with bare domain Host header (exempt from tenant guard)."""
        import settings

        response = client.get(
            "/caddy/check-domain",
            params={"domain": settings.BASE_DOMAIN},
            headers={"host": settings.BASE_DOMAIN},
        )

        assert response.status_code == 200

    def test_www_subdomain_returns_404(self, client: TestClient):
        """www subdomain is not a valid tenant and returns 404."""
        import settings

        domain = f"www.{settings.BASE_DOMAIN}"
        response = client.get("/caddy/check-domain", params={"domain": domain})

        assert response.status_code == 404
