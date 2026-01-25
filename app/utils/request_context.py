"""Request context using contextvars for automatic propagation.

This module provides request-scoped context that automatically propagates
through async call chains. Used by middleware to set context at request
start, and by log_event to automatically capture request metadata.

For background jobs or CLI commands that run outside web requests,
use the system_context() context manager to bypass the context requirement.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, TypedDict

# The contextvar holding request metadata (IP, user agent, device, session hash)
_request_context: ContextVar[dict[str, Any] | None] = ContextVar("request_context", default=None)

# Marker for system/background context (legitimate no-metadata scenario)
_system_context: ContextVar[bool] = ContextVar("system_context", default=False)


class ApiClientContext(TypedDict):
    """Context for API client that made the request."""

    client_id: str
    client_name: str
    client_type: str  # "normal" or "b2b"


# The contextvar holding API client info (only set for OAuth2 token-authenticated requests)
_api_client_context: ContextVar[ApiClientContext | None] = ContextVar(
    "api_client_context", default=None
)


def get_request_context() -> dict[str, Any] | None:
    """Get current request context, or None if not set."""
    return _request_context.get()


def set_request_context(metadata: dict[str, Any]) -> None:
    """Set request context for current async context."""
    _request_context.set(metadata)


def clear_request_context() -> None:
    """Clear request context."""
    _request_context.set(None)


def is_system_context() -> bool:
    """Check if in system context (background job, CLI command)."""
    return _system_context.get()


@contextmanager
def system_context():
    """
    Context manager for system/background operations.

    Use this when running code outside of a web request context,
    such as background jobs, CLI commands, scheduled tasks, or tests.

    Example:
        with system_context():
            service.do_background_work()
    """
    token = _system_context.set(True)
    try:
        yield
    finally:
        _system_context.reset(token)


def get_api_client_context() -> ApiClientContext | None:
    """Get current API client context, or None if not an API request."""
    return _api_client_context.get()


def set_api_client_context(client_id: str, client_name: str, client_type: str) -> None:
    """Set API client context for current async context.

    Called by API dependencies after validating an OAuth2 token to record
    which API client made the request.

    Args:
        client_id: The OAuth2 client ID
        client_name: Human-readable name of the client
        client_type: "normal" (authorization code) or "b2b" (client credentials)
    """
    _api_client_context.set(
        ApiClientContext(
            client_id=client_id,
            client_name=client_name,
            client_type=client_type,
        )
    )


def clear_api_client_context() -> None:
    """Clear API client context."""
    _api_client_context.set(None)
