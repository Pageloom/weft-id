"""ASGI middleware that rejects request bodies exceeding a size limit.

Checks the Content-Length header before the body is read. If absent or
within the limit, the request proceeds normally. Requests advertising a
body larger than the limit receive 413 Payload Too Large.
"""

from starlette.types import ASGIApp, Receive, Scope, Send

_DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB


class BodyLimitMiddleware:
    """Reject requests whose Content-Length exceeds *max_bytes*."""

    def __init__(self, app: ASGIApp, *, max_bytes: int = _DEFAULT_MAX_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                length = int(cl)
            except (ValueError, TypeError):
                length = 0
            if length > self.max_bytes:
                response_body = b"Request body too large"
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(response_body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": response_body})
                return

        await self.app(scope, receive, send)
