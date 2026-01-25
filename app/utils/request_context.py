"""Request context using contextvars for automatic propagation.

This module provides request-scoped context that automatically propagates
through async call chains. Used by middleware to set context at request
start, and by log_event to automatically capture request metadata.

For background jobs or CLI commands that run outside web requests,
use the system_context() context manager to bypass the context requirement.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

# The contextvar holding request metadata (IP, user agent, device, session hash)
_request_context: ContextVar[dict[str, Any] | None] = ContextVar("request_context", default=None)

# Marker for system/background context (legitimate no-metadata scenario)
_system_context: ContextVar[bool] = ContextVar("system_context", default=False)


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
