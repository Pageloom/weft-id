"""Service layer exceptions.

These exceptions are HTTP-agnostic but include error codes and messages
that can be translated to HTTP responses (API) or error pages (HTML).
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ServiceError(Exception):
    """Base class for all service layer exceptions.

    Attributes:
        message: Human-readable error message
        code: Machine-readable error code (e.g., "domain_exists", "invalid_timeout")
        details: Optional dict with additional context
    """

    message: str
    code: str = "error"
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


@dataclass
class NotFoundError(ServiceError):
    """Resource was not found.

    Translates to: HTTP 404, error page with "Not Found" title
    """

    code: str = "not_found"


@dataclass
class ForbiddenError(ServiceError):
    """User lacks permission to perform this action.

    Translates to: HTTP 403, error page with "Access Denied" title

    Note: This is for authorization failures (user authenticated but not allowed).
    Authentication failures are handled at the route/dependency level.
    """

    code: str = "forbidden"
    required_role: str | None = None


@dataclass
class ValidationError(ServiceError):
    """Input validation failed.

    Translates to: HTTP 400, error page with "Invalid Input" title
    """

    code: str = "validation_error"
    field: str | None = None  # Which field failed validation


@dataclass
class ConflictError(ServiceError):
    """Resource already exists or state conflict.

    Translates to: HTTP 409, error page with "Conflict" title
    """

    code: str = "conflict"
