"""Error handling utilities for service layer exceptions."""

from fastapi import HTTPException, Request
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ServiceError,
    ValidationError,
)
from starlette.responses import Response
from utils.template_context import get_template_context
from utils.templates import templates


def translate_to_http_exception(exc: ServiceError) -> HTTPException:
    """Convert a service exception to an HTTPException for API routes."""
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=404, detail=exc.message)

    if isinstance(exc, ForbiddenError):
        return HTTPException(status_code=403, detail=exc.message)

    if isinstance(exc, ValidationError):
        return HTTPException(status_code=400, detail=exc.message)

    if isinstance(exc, ConflictError):
        return HTTPException(status_code=409, detail=exc.message)

    if isinstance(exc, RateLimitError):
        return HTTPException(
            status_code=429,
            detail=exc.message,
            headers={"Retry-After": str(exc.retry_after)},
        )

    # Default fallback
    return HTTPException(status_code=500, detail=exc.message)


def render_error_page(
    request: Request,
    tenant_id: str,
    exc: ServiceError,
) -> Response:
    """Render an error page for HTML routes."""
    # Map exception types to error page content
    headers = {}
    if isinstance(exc, NotFoundError):
        status_code = 404
        error_title = "Not Found"
    elif isinstance(exc, ForbiddenError):
        status_code = 403
        error_title = "Access Denied"
    elif isinstance(exc, ValidationError):
        status_code = 400
        error_title = "Invalid Input"
    elif isinstance(exc, ConflictError):
        status_code = 409
        error_title = "Conflict"
    elif isinstance(exc, RateLimitError):
        status_code = 429
        error_title = "Too Many Requests"
        headers["Retry-After"] = str(exc.retry_after)
    else:
        status_code = 500
        error_title = "Error"

    context = get_template_context(
        request,
        tenant_id,
        error_title=error_title,
        error_message=exc.message,
        error_code=exc.code,
    )

    response = templates.TemplateResponse(
        request,
        "error.html",
        context,
        status_code=status_code,
    )
    for key, value in headers.items():
        response.headers[key] = value
    return response
