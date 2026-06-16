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
        assert "yourcompany.weft.id" in response.text


def _insert_verified_domain(tenant_id, domain, portal_host):
    import database

    return database.protected_domains.create_protected_domain(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        domain=domain,
        portal_host=portal_host,
        created_by=None,
        verification_status="verified",
    )


class TestForwardAuthHostResolution:
    """Tenant resolution from a protected-domain portal host for /forward-auth/*."""

    def test_unknown_forward_auth_host_fails_closed(self, client: TestClient):
        """A /forward-auth request on an unrecognized external host returns 404."""
        response = client.get("/forward-auth/check", headers={"host": "auth.unregistered-fa.com"})

        assert response.status_code == 404
        assert response.json()["detail"] == "Unknown forward-auth host"

    def test_verified_portal_host_passes_guard(self, client: TestClient, test_tenant):
        """A verified portal host passes the guard and reaches the /check route.

        The route now exists (Iteration 5). With no proxy app fronting the host
        it fails closed at the handler with 403 (deny), NOT the middleware's
        fail-closed 404. The point is the request is admitted past the guard.
        """
        _insert_verified_domain(test_tenant["id"], "faresolve.com", "auth.faresolve.com")

        response = client.get("/forward-auth/check", headers={"host": "auth.faresolve.com"})

        # Handler-level deny (no app configured), not the middleware's 404.
        assert response.status_code == 403

    def test_forward_auth_on_tenant_subdomain_passes_guard(self, client: TestClient, test_tenant):
        """A /forward-auth request on a normal tenant subdomain is not fail-closed."""
        import settings

        host = f"{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"
        # /authorize requires domain + portal_host query params; omitting them
        # yields FastAPI's 422 (validation), proving the guard admitted the
        # request rather than rejecting it with the fail-closed 404.
        response = client.get("/forward-auth/authorize", headers={"host": host})

        assert response.status_code == 422
        assert response.json().get("detail") != "Unknown forward-auth host"

    def test_check_subrequest_resolves_from_host_not_forwarded_app_host(
        self, client: TestClient, test_tenant
    ):
        """On a /check subrequest, tenant resolves from the portal Host header.

        The real proxy shape sends Host=<portal host> and X-Forwarded-Host=<the
        original app host>. The app host is NOT a verified portal host, so the
        guard must resolve the tenant from Host (candidate order: Host first) and
        admit the request to the handler, not fail closed with 404.
        """
        _insert_verified_domain(test_tenant["id"], "candorder.com", "auth.candorder.com")

        response = client.get(
            "/forward-auth/check",
            headers={
                "host": "auth.candorder.com",
                "x-forwarded-host": "grafana.candorder.com",
                "x-forwarded-uri": "/",
            },
        )

        # Admitted past the guard: the handler runs and fails closed with 403
        # (no proxy app configured), NOT the middleware's 404 "unknown host".
        assert response.status_code == 403

    def test_unverified_portal_host_fails_closed(self, client: TestClient, test_tenant):
        """A registered-but-UNVERIFIED portal host is not admitted (fails closed).

        resolve_verified_portal_host gates on verification_status='verified'; a
        pending domain must yield the middleware's 404, never tenant context.
        """
        import database

        database.protected_domains.create_protected_domain(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            domain="pending-fa.com",
            portal_host="auth.pending-fa.com",
            created_by=None,
            verification_status="pending",
        )

        response = client.get("/forward-auth/check", headers={"host": "auth.pending-fa.com"})

        assert response.status_code == 404
        assert response.json()["detail"] == "Unknown forward-auth host"
