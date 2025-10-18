"""Custom session middleware to support per-tenant session configuration."""

from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class DynamicSessionMiddleware(SessionMiddleware):
    """Extended SessionMiddleware that supports dynamic max_age per session.

    This middleware allows each session to specify its own max_age value
    by setting '_max_age' in the session data. This enables per-tenant
    control over session persistence (whether sessions survive browser close).

    When _max_age is None, the session cookie will expire when browser closes.
    When _max_age is a number, the session cookie will persist for that many seconds.
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process the request and apply dynamic max_age from session."""
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                # Get session data from scope
                session = scope.get("session", {})

                # Check if session specifies a custom max_age
                if "_max_age" in session:
                    custom_max_age = session.get("_max_age")

                    # Find and modify the session cookie header
                    headers = message.get("headers", [])
                    for idx, (name, value) in enumerate(headers):
                        if name == b"set-cookie":
                            cookie_str = value.decode("latin-1")

                            # Check if this is the session cookie
                            if cookie_str.startswith(f"{self.session_cookie}="):
                                # Parse cookie parts
                                parts = [p.strip() for p in cookie_str.split(";")]
                                new_parts = []

                                # Keep all parts except Max-Age and Expires
                                for part in parts:
                                    lower_part = part.lower()
                                    if not (lower_part.startswith("max-age=") or lower_part.startswith("expires=")):
                                        new_parts.append(part)

                                # Add Max-Age if specified (persistent session)
                                if custom_max_age is not None:
                                    new_parts.append(f"Max-Age={custom_max_age}")
                                # If custom_max_age is None, omit Max-Age (session cookie)

                                # Rebuild cookie string
                                new_cookie_str = "; ".join(new_parts)
                                headers[idx] = (b"set-cookie", new_cookie_str.encode("latin-1"))
                                break

            await send(message)

        # Call parent SessionMiddleware with our custom send wrapper
        await super().__call__(scope, receive, send_wrapper)
