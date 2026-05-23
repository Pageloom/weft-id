"""Tests for middleware.body_limit."""

from middleware.body_limit import BodyLimitMiddleware
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient


async def _echo(request: Request) -> PlainTextResponse:
    body = await request.body()
    return PlainTextResponse(f"OK:{len(body)}")


def _make_app(max_bytes: int = 1024) -> Starlette:
    app = Starlette(routes=[Route("/echo", _echo, methods=["POST"])])
    app.add_middleware(BodyLimitMiddleware, max_bytes=max_bytes)
    return app


def test_small_body_passes():
    client = TestClient(_make_app(max_bytes=1024))
    response = client.post("/echo", content=b"x" * 512)
    assert response.status_code == 200
    assert response.text == "OK:512"


def test_oversized_body_rejected():
    client = TestClient(_make_app(max_bytes=256))
    response = client.post("/echo", content=b"x" * 512)
    assert response.status_code == 413
    assert "too large" in response.text.lower()


def test_no_content_length_passes():
    """Requests without Content-Length header are not rejected."""
    client = TestClient(_make_app(max_bytes=64))
    response = client.post("/echo", content=b"")
    assert response.status_code == 200


def test_non_http_requests_pass():
    """WebSocket (non-HTTP) connections pass through."""
    app = _make_app(max_bytes=1)
    # GET with no body should pass
    client = TestClient(app)
    response = client.post("/echo", content=b"")
    assert response.status_code == 200


def test_exact_limit_passes():
    client = TestClient(_make_app(max_bytes=100))
    response = client.post("/echo", content=b"x" * 100)
    assert response.status_code == 200


def test_one_over_limit_rejected():
    client = TestClient(_make_app(max_bytes=100))
    response = client.post("/echo", content=b"x" * 101)
    assert response.status_code == 413
