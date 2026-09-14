"""Integration tests for CSRF middleware.

These tests verify the CSRFMiddleware actually works with a real FastAPI application,
testing the full request/response cycle.
"""

import os
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from middleware.csrf import (
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    CSRF_SESSION_KEY,
    CSRFMiddleware,
)
from starlette.middleware.sessions import SessionMiddleware


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def csrf_app():
    """Create a test FastAPI app with CSRF middleware."""
    app = FastAPI()

    # Add CSRF middleware FIRST (middlewares are applied in reverse order)
    app.add_middleware(CSRFMiddleware)

    # Add session middleware AFTER (will run first in request processing)
    app.add_middleware(SessionMiddleware, secret_key="test-secret-key")

    # Test routes
    @app.get("/csrf-token")
    async def get_token(request: Request):
        """Endpoint to get CSRF token for testing."""
        token = request.session.get(CSRF_SESSION_KEY)
        if not token:
            from middleware.csrf import generate_csrf_token

            token = generate_csrf_token()
            request.session[CSRF_SESSION_KEY] = token
        return {"csrf_token": token}

    @app.post("/test-form")
    async def test_form(request: Request):
        """Protected endpoint that requires CSRF token.

        Echoes the form so tests can prove the body survives the middleware's
        own form parsing (BaseHTTPMiddleware replays only a body read via
        ``request.body()``).
        """
        form = await request.form()
        fields = {k: (v if isinstance(v, str) else v.filename) for k, v in form.items()}
        return {"status": "success", "form": fields}

    @app.post("/test-json")
    async def test_json():
        """Protected endpoint for JSON requests."""
        return {"status": "success"}

    @app.post("/api/test")
    async def api_test():
        """API endpoint (exempt from CSRF)."""
        return {"status": "api_success"}

    return app


@pytest.fixture
def csrf_client(csrf_app):
    """Create a test client for the CSRF-protected app."""
    from fastapi.testclient import TestClient

    return TestClient(csrf_app)


def test_csrf_token_from_header_ajax(csrf_client):
    """Test CSRF token validation from X-CSRF-Token header (AJAX requests)."""
    # First, get a CSRF token by making a GET request
    # TestClient maintains session automatically via cookies
    response = csrf_client.get("/csrf-token")
    assert response.status_code == 200
    csrf_token = response.json()["csrf_token"]

    # Make POST request with token in header
    # Session is maintained automatically
    response = csrf_client.post(
        "/test-json",
        headers={CSRF_HEADER_NAME: csrf_token},
        json={"data": "value"},
    )

    # Should succeed
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_csrf_token_from_form_urlencoded(csrf_client):
    """Test CSRF token validation from URL-encoded form data."""
    # Get CSRF token
    response = csrf_client.get("/csrf-token")
    csrf_token = response.json()["csrf_token"]

    # Submit form with token (session maintained automatically)
    response = csrf_client.post(
        "/test-form",
        data={CSRF_FORM_FIELD: csrf_token, "other_field": "value"},
    )

    # Should succeed, and the handler must still see the whole form
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["form"] == {CSRF_FORM_FIELD: csrf_token, "other_field": "value"}


def test_csrf_token_from_multipart_form(csrf_client):
    """Test CSRF token validation from multipart form data."""
    # Get CSRF token
    response = csrf_client.get("/csrf-token")
    csrf_token = response.json()["csrf_token"]

    # Submit multipart form with token (session maintained automatically)
    response = csrf_client.post(
        "/test-form",
        data={CSRF_FORM_FIELD: csrf_token},
        files={"file": ("test.txt", b"test content", "text/plain")},
    )

    # Should succeed, and the handler must still see the fields and the file
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["form"] == {CSRF_FORM_FIELD: csrf_token, "file": "test.txt"}


def test_csrf_token_mismatch_returns_403_html(csrf_client):
    """Test that token mismatch returns 403 with HTML response."""
    # Get CSRF token to establish session
    response = csrf_client.get("/csrf-token")

    # Submit with wrong token (session maintained automatically)
    response = csrf_client.post(
        "/test-form",
        data={CSRF_FORM_FIELD: "wrong-token-12345"},
    )

    # Should return 403
    assert response.status_code == 403
    assert "CSRF token validation failed" in response.text
    assert "text/html" in response.headers.get("content-type", "")


def test_csrf_token_mismatch_returns_403_json(csrf_client):
    """Test that token mismatch returns 403 with JSON response when Accept: application/json."""
    # Get CSRF token to establish session
    response = csrf_client.get("/csrf-token")

    # Submit with wrong token but Accept: application/json (session maintained automatically)
    response = csrf_client.post(
        "/test-json",
        headers={
            "Accept": "application/json",
            CSRF_HEADER_NAME: "wrong-token",
        },
        json={"data": "value"},
    )

    # Should return 403 with JSON
    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF token validation failed"


def test_csrf_missing_token_returns_403(csrf_client):
    """Test that missing CSRF token returns 403."""
    # Make POST without establishing session or providing token
    response = csrf_client.post(
        "/test-form",
        data={"other_field": "value"},
    )

    # Should return 403
    assert response.status_code == 403


def test_csrf_exempt_routes_bypass_validation(csrf_client):
    """Test that exempt routes (API, SAML ACS, OAuth2) bypass CSRF validation."""
    # API route should work without CSRF token
    response = csrf_client.post("/api/test", json={"data": "value"})

    # Should succeed
    assert response.status_code == 200
    assert response.json()["status"] == "api_success"


def test_csrf_custom_error_handler(csrf_app):
    """Test CSRF middleware with custom error handler."""
    from fastapi.testclient import TestClient

    # Custom error handler
    def custom_handler(request: Request):
        return JSONResponse(
            {"custom_error": "CSRF validation failed with custom handler"},
            status_code=418,  # I'm a teapot
        )

    # Recreate app with custom handler (middleware order matters!)
    app = FastAPI()
    app.add_middleware(CSRFMiddleware, error_handler=custom_handler)
    app.add_middleware(SessionMiddleware, secret_key="test-secret-key")

    @app.post("/test")
    async def test():
        return {"status": "success"}

    client = TestClient(app)

    # Establish session first
    @app.get("/setup")
    async def setup(request: Request):
        # Force session creation
        request.session["initialized"] = True
        return {"status": "ok"}

    client.get("/setup")

    # POST without CSRF token should trigger custom handler
    response = client.post("/test", data={"field": "value"})

    assert response.status_code == 418
    assert response.json()["custom_error"] == "CSRF validation failed with custom handler"


def test_csrf_safe_methods_bypass_validation(csrf_client):
    """Test that safe methods (GET) bypass CSRF validation."""
    # GET should work without CSRF token
    response = csrf_client.get("/csrf-token")
    assert response.status_code == 200

    # Verify we can GET without any CSRF considerations
    assert "csrf_token" in response.json()


def test_csrf_no_session_available_rejects_request(caplog):
    """No session in scope means the token cannot be checked: fail closed.

    This is the misordering case (CSRF registered after, so running outside
    of, the session middleware). It used to fail open, which silently
    disabled CSRF for the whole app for eleven months.
    """
    from fastapi.testclient import TestClient

    # Create app WITHOUT session middleware
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/test")
    async def test():
        return {"status": "success"}

    client = TestClient(app)

    with caplog.at_level("ERROR", logger="middleware.csrf"):
        response = client.post("/test", data={"field": "value"})

    assert response.status_code == 403
    assert "CSRF" in response.text
    assert any("no session in request scope" in r.getMessage() for r in caplog.records)


def test_csrf_misordered_session_middleware_rejects_request():
    """Session middleware registered BEFORE (inside) CSRF is the real-world bug shape."""
    from fastapi.testclient import TestClient

    app = FastAPI()
    # Wrong order: session added first becomes the inner layer, so the CSRF
    # middleware runs before the session is decoded.
    app.add_middleware(SessionMiddleware, secret_key="test-secret-key")
    app.add_middleware(CSRFMiddleware)

    @app.post("/test")
    async def test():
        return {"status": "success"}

    client = TestClient(app)
    response = client.post("/test", data={"field": "value"})
    assert response.status_code == 403


def test_csrf_reads_session_from_scope_not_request_property(csrf_client, mocker):
    """The middleware must use the real signed session even if ``Request.session`` is patched.

    Router tests replace ``starlette.requests.Request.session`` with a plain
    dict for the handler's benefit. The CSRF layer reads the ASGI scope
    directly so that the cookie-backed token still counts.
    """
    token_response = csrf_client.get("/csrf-token")
    token = token_response.json()["csrf_token"]

    mocker.patch("starlette.requests.Request.session", {})

    response = csrf_client.post("/test-form", headers={CSRF_HEADER_NAME: token})
    assert response.status_code == 200
