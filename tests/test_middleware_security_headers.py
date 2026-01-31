"""Tests for security headers middleware."""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


def test_security_headers_on_html_routes(client, test_tenant_host):
    """Test that security headers are present on HTML routes."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    assert response.status_code == 200

    # Verify all security headers are present
    assert "Content-Security-Policy" in response.headers
    assert "X-Frame-Options" in response.headers
    assert "X-Content-Type-Options" in response.headers
    assert "Referrer-Policy" in response.headers

    # Note: HSTS is only added on HTTPS connections,
    # test client uses HTTP so HSTS should not be present
    assert "Strict-Transport-Security" not in response.headers


def test_security_headers_on_api_routes(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that security headers are present on API routes."""
    headers = {**oauth2_admin_authorization_header, "Host": test_tenant_host}
    response = client.get("/api/v1/users/me", headers=headers)

    assert response.status_code == 200

    # Verify all security headers are present (API routes get headers too)
    assert "Content-Security-Policy" in response.headers
    assert "X-Frame-Options" in response.headers
    assert "X-Content-Type-Options" in response.headers
    assert "Referrer-Policy" in response.headers


def test_csp_header_value(client, test_tenant_host):
    """Test Content-Security-Policy header value."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    csp = response.headers.get("Content-Security-Policy", "")

    # Verify CSP includes expected directives
    assert "default-src 'self'" in csp
    # script-src uses nonce instead of unsafe-inline
    assert "script-src 'self' 'nonce-" in csp
    assert "img-src 'self' data:" in csp
    # style-src uses nonce instead of unsafe-inline
    assert "style-src 'self' 'nonce-" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp


def test_x_frame_options_header_value(client, test_tenant_host):
    """Test X-Frame-Options header value."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    assert response.headers.get("X-Frame-Options") == "DENY"


def test_x_content_type_options_header_value(client, test_tenant_host):
    """Test X-Content-Type-Options header value."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    assert response.headers.get("X-Content-Type-Options") == "nosniff"


def test_referrer_policy_header_value(client, test_tenant_host):
    """Test Referrer-Policy header value."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_hsts_not_added_on_http(client, test_tenant_host):
    """Test that HSTS header is not added on HTTP connections."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    # TestClient uses HTTP, so HSTS should not be present
    assert "Strict-Transport-Security" not in response.headers


def test_security_headers_on_redirects(client, test_tenant_host):
    """Test that security headers are present on redirect responses."""
    # Request a page that redirects (unauthenticated access to protected route)
    response = client.get("/dashboard", headers={"Host": test_tenant_host}, follow_redirects=False)

    # Should redirect to login
    assert response.status_code == 303

    # Verify security headers are present even on redirects
    assert "Content-Security-Policy" in response.headers
    assert "X-Frame-Options" in response.headers
    assert "X-Content-Type-Options" in response.headers
    assert "Referrer-Policy" in response.headers


def test_security_headers_on_404(client, test_tenant_host):
    """Test that security headers are present on 404 responses."""
    response = client.get("/nonexistent-route", headers={"Host": test_tenant_host})

    assert response.status_code == 404

    # Verify security headers are present even on error pages
    assert "Content-Security-Policy" in response.headers
    assert "X-Frame-Options" in response.headers
    assert "X-Content-Type-Options" in response.headers
    assert "Referrer-Policy" in response.headers


def test_security_headers_do_not_duplicate(client, test_tenant_host):
    """Test that security headers are not duplicated in responses."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    # Get all header keys and check for duplicates
    header_keys = list(response.headers.keys())

    # Count occurrences of each security header
    csp_count = sum(1 for key in header_keys if key.lower() == "content-security-policy")
    xfo_count = sum(1 for key in header_keys if key.lower() == "x-frame-options")
    xcto_count = sum(1 for key in header_keys if key.lower() == "x-content-type-options")
    rp_count = sum(1 for key in header_keys if key.lower() == "referrer-policy")

    # Each header should appear exactly once
    assert csp_count == 1
    assert xfo_count == 1
    assert xcto_count == 1
    assert rp_count == 1


def test_csp_blocks_external_domains(client, test_tenant_host):
    """Test that CSP does not allow external domains (QR codes and CSS are local)."""
    # Check the login page for CSP (any page will have the same CSP)
    response = client.get("/login", headers={"Host": test_tenant_host})

    csp = response.headers.get("Content-Security-Policy", "")

    # Verify CSP does NOT allow external domains
    # QR codes are now generated locally, not from api.qrserver.com
    assert "api.qrserver.com" not in csp
    # Tailwind CSS is now built locally, not from cdn.tailwindcss.com
    assert "cdn.tailwindcss.com" not in csp


def test_csp_allows_inline_styles_with_nonce(client, test_tenant_host):
    """Test that CSP allows inline styles via nonce."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    csp = response.headers.get("Content-Security-Policy", "")

    # Verify CSP uses nonce for styles (safer than unsafe-inline)
    assert "style-src 'self' 'nonce-" in csp


def test_csp_prevents_frames(client, test_tenant_host):
    """Test that CSP prevents the page from being framed."""
    response = client.get("/login", headers={"Host": test_tenant_host})

    csp = response.headers.get("Content-Security-Policy", "")

    # Verify CSP includes frame-ancestors 'none'
    assert "frame-ancestors 'none'" in csp
