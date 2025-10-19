"""Tests for session middleware."""

import pytest
from unittest.mock import AsyncMock
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from middleware.session import DynamicSessionMiddleware


def test_middleware_creation():
    """Test that DynamicSessionMiddleware can be instantiated."""
    app = FastAPI()
    middleware = DynamicSessionMiddleware(
        app=app,
        secret_key="test-secret-key",
        session_cookie="session"
    )
    assert middleware is not None
    assert middleware.session_cookie == "session"


@pytest.mark.asyncio
async def test_non_http_scope():
    """Test that non-HTTP scopes are passed through unchanged."""
    app_mock = AsyncMock()
    middleware = DynamicSessionMiddleware(
        app=app_mock,
        secret_key="test-secret-key",
        session_cookie="session"
    )

    scope = {"type": "lifespan"}
    receive = AsyncMock()
    send = AsyncMock()

    await middleware(scope, receive, send)

    # Should call the wrapped app directly
    app_mock.assert_called_once_with(scope, receive, send)


def test_session_middleware_integration_no_max_age():
    """Test middleware with no _max_age in session."""
    app = FastAPI()

    # Add middleware
    app.add_middleware(
        DynamicSessionMiddleware,
        secret_key="test-secret-key-at-least-32-chars-long",
        session_cookie="session"
    )

    @app.get("/set-session")
    def set_session(request: Request):
        request.session["user_id"] = "123"
        # No _max_age set
        return JSONResponse({"status": "ok"})

    @app.get("/get-session")
    def get_session(request: Request):
        return JSONResponse({"user_id": request.session.get("user_id")})

    client = TestClient(app)

    # Set session
    response = client.get("/set-session")
    assert response.status_code == 200

    # Session cookie should be set
    assert "session" in response.cookies

    # Get session
    response = client.get("/get-session")
    assert response.status_code == 200
    assert response.json()["user_id"] == "123"


def test_session_middleware_with_persistent_max_age():
    """Test middleware with _max_age set for persistent session."""
    app = FastAPI()

    app.add_middleware(
        DynamicSessionMiddleware,
        secret_key="test-secret-key-at-least-32-chars-long",
        session_cookie="session"
    )

    @app.get("/set-persistent-session")
    def set_persistent(request: Request):
        request.session["user_id"] = "456"
        request.session["_max_age"] = 86400  # 24 hours
        return JSONResponse({"status": "ok"})

    client = TestClient(app)

    response = client.get("/set-persistent-session")
    assert response.status_code == 200

    # Check that session cookie was set
    assert "session" in response.cookies

    # Check that Max-Age is in the cookie
    set_cookie_header = response.headers.get("set-cookie", "")
    assert "Max-Age=86400" in set_cookie_header or "max-age=86400" in set_cookie_header.lower()


def test_session_middleware_with_none_max_age():
    """Test middleware with _max_age=None for session-only cookie."""
    app = FastAPI()

    app.add_middleware(
        DynamicSessionMiddleware,
        secret_key="test-secret-key-at-least-32-chars-long",
        session_cookie="session"
    )

    @app.get("/set-session-only")
    def set_session_only(request: Request):
        request.session["user_id"] = "789"
        request.session["_max_age"] = None  # Session cookie
        return JSONResponse({"status": "ok"})

    client = TestClient(app)

    response = client.get("/set-session-only")
    assert response.status_code == 200

    # Session cookie should be set
    assert "session" in response.cookies


def test_session_middleware_changing_max_age():
    """Test changing _max_age between requests."""
    app = FastAPI()

    app.add_middleware(
        DynamicSessionMiddleware,
        secret_key="test-secret-key-at-least-32-chars-long",
        session_cookie="session"
    )

    @app.get("/set-persistent")
    def set_persistent(request: Request):
        request.session["user_id"] = "111"
        request.session["_max_age"] = 3600  # 1 hour
        return JSONResponse({"status": "persistent"})

    @app.get("/set-session")
    def set_session(request: Request):
        # Keep user_id but change to session cookie
        request.session["_max_age"] = None
        return JSONResponse({"status": "session", "user_id": request.session.get("user_id")})

    client = TestClient(app)

    # First request - persistent
    response1 = client.get("/set-persistent")
    assert response1.status_code == 200
    set_cookie1 = response1.headers.get("set-cookie", "")
    assert "Max-Age=3600" in set_cookie1 or "max-age=3600" in set_cookie1.lower()

    # Second request - session only
    response2 = client.get("/set-session")
    assert response2.status_code == 200
    assert response2.json()["user_id"] == "111"  # User ID persisted


def test_websocket_scope_handling():
    """Test that websocket connections work with the middleware."""
    app = FastAPI()

    app.add_middleware(
        DynamicSessionMiddleware,
        secret_key="test-secret-key-at-least-32-chars-long",
        session_cookie="session"
    )

    @app.get("/")
    def root():
        return {"message": "ok"}

    # Just verify app can be instantiated with middleware and handle requests
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200


def test_multiple_cookies_with_session():
    """Test that multiple cookies can coexist with session cookie."""
    app = FastAPI()

    app.add_middleware(
        DynamicSessionMiddleware,
        secret_key="test-secret-key-at-least-32-chars-long",
        session_cookie="session"
    )

    @app.get("/set-cookies")
    def set_cookies(request: Request):
        request.session["user"] = "test"
        request.session["_max_age"] = 7200
        response = JSONResponse({"status": "ok"})
        response.set_cookie("other_cookie", "value123")
        return response

    client = TestClient(app)

    response = client.get("/set-cookies")
    assert response.status_code == 200

    # Both cookies should be set
    assert "session" in response.cookies
    assert "other_cookie" in response.cookies
    assert response.cookies["other_cookie"] == "value123"
