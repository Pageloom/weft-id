"""Comprehensive tests for Service Errors utility module.

This test file covers all error handling utilities in utils/service_errors.py.
Tests include:
- translate_to_http_exception for all exception types
- render_error_page for all exception types
- Template rendering with correct context
"""

from unittest.mock import MagicMock, patch

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)

# =============================================================================
# translate_to_http_exception Tests
# =============================================================================


def test_translate_not_found_error_to_404():
    """Test NotFoundError translates to 404 HTTP exception."""
    from utils.service_errors import translate_to_http_exception

    exc = NotFoundError(message="Resource not found", code="not_found")

    result = translate_to_http_exception(exc)

    assert isinstance(result, HTTPException)
    assert result.status_code == 404
    assert result.detail == "Resource not found"


def test_translate_forbidden_error_to_403():
    """Test ForbiddenError translates to 403 HTTP exception."""
    from utils.service_errors import translate_to_http_exception

    exc = ForbiddenError(message="Access denied", code="forbidden")

    result = translate_to_http_exception(exc)

    assert isinstance(result, HTTPException)
    assert result.status_code == 403
    assert result.detail == "Access denied"


def test_translate_validation_error_to_400():
    """Test ValidationError translates to 400 HTTP exception."""
    from utils.service_errors import translate_to_http_exception

    exc = ValidationError(message="Invalid input", code="invalid_input", field="email")

    result = translate_to_http_exception(exc)

    assert isinstance(result, HTTPException)
    assert result.status_code == 400
    assert result.detail == "Invalid input"


def test_translate_conflict_error_to_409():
    """Test ConflictError translates to 409 HTTP exception."""
    from utils.service_errors import translate_to_http_exception

    exc = ConflictError(message="Resource already exists", code="conflict")

    result = translate_to_http_exception(exc)

    assert isinstance(result, HTTPException)
    assert result.status_code == 409
    assert result.detail == "Resource already exists"


def test_translate_generic_service_error_to_500():
    """Test generic ServiceError translates to 500 HTTP exception."""
    from utils.service_errors import translate_to_http_exception

    exc = ServiceError(message="Internal error", code="internal_error")

    result = translate_to_http_exception(exc)

    assert isinstance(result, HTTPException)
    assert result.status_code == 500
    assert result.detail == "Internal error"


# =============================================================================
# render_error_page Tests
# =============================================================================


def test_render_not_found_error_page():
    """Test rendering 404 error page for NotFoundError."""
    from utils.service_errors import render_error_page

    mock_request = MagicMock(spec=Request)
    exc = NotFoundError(message="Page not found", code="not_found")

    with patch("utils.service_errors.get_template_context") as mock_context:
        with patch("utils.service_errors.templates") as mock_templates:
            mock_context.return_value = {"error_title": "Not Found"}
            mock_templates.TemplateResponse.return_value = HTMLResponse(
                content="<html>404</html>", status_code=404
            )

            result = render_error_page(mock_request, "tenant-123", exc)

            assert isinstance(result, HTMLResponse)
            mock_context.assert_called_once_with(
                mock_request,
                "tenant-123",
                error_title="Not Found",
                error_message="Page not found",
                error_code="not_found",
            )
            mock_templates.TemplateResponse.assert_called_once()
            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 404


def test_render_forbidden_error_page():
    """Test rendering 403 error page for ForbiddenError."""
    from utils.service_errors import render_error_page

    mock_request = MagicMock(spec=Request)
    exc = ForbiddenError(message="Access denied", code="forbidden")

    with patch("utils.service_errors.get_template_context") as mock_context:
        with patch("utils.service_errors.templates") as mock_templates:
            mock_context.return_value = {"error_title": "Access Denied"}
            mock_templates.TemplateResponse.return_value = HTMLResponse(
                content="<html>403</html>", status_code=403
            )

            result = render_error_page(mock_request, "tenant-123", exc)

            assert isinstance(result, HTMLResponse)
            mock_context.assert_called_once_with(
                mock_request,
                "tenant-123",
                error_title="Access Denied",
                error_message="Access denied",
                error_code="forbidden",
            )
            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 403


def test_render_validation_error_page():
    """Test rendering 400 error page for ValidationError."""
    from utils.service_errors import render_error_page

    mock_request = MagicMock(spec=Request)
    exc = ValidationError(message="Invalid data", code="validation_error", field="email")

    with patch("utils.service_errors.get_template_context") as mock_context:
        with patch("utils.service_errors.templates") as mock_templates:
            mock_context.return_value = {"error_title": "Invalid Input"}
            mock_templates.TemplateResponse.return_value = HTMLResponse(
                content="<html>400</html>", status_code=400
            )

            result = render_error_page(mock_request, "tenant-123", exc)

            assert isinstance(result, HTMLResponse)
            mock_context.assert_called_once_with(
                mock_request,
                "tenant-123",
                error_title="Invalid Input",
                error_message="Invalid data",
                error_code="validation_error",
            )
            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 400


def test_render_conflict_error_page():
    """Test rendering 409 error page for ConflictError."""
    from utils.service_errors import render_error_page

    mock_request = MagicMock(spec=Request)
    exc = ConflictError(message="Resource conflict", code="conflict")

    with patch("utils.service_errors.get_template_context") as mock_context:
        with patch("utils.service_errors.templates") as mock_templates:
            mock_context.return_value = {"error_title": "Conflict"}
            mock_templates.TemplateResponse.return_value = HTMLResponse(
                content="<html>409</html>", status_code=409
            )

            result = render_error_page(mock_request, "tenant-123", exc)

            assert isinstance(result, HTMLResponse)
            mock_context.assert_called_once_with(
                mock_request,
                "tenant-123",
                error_title="Conflict",
                error_message="Resource conflict",
                error_code="conflict",
            )
            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 409


def test_render_generic_service_error_page():
    """Test rendering 500 error page for generic ServiceError."""
    from utils.service_errors import render_error_page

    mock_request = MagicMock(spec=Request)
    exc = ServiceError(message="Something went wrong", code="internal_error")

    with patch("utils.service_errors.get_template_context") as mock_context:
        with patch("utils.service_errors.templates") as mock_templates:
            mock_context.return_value = {"error_title": "Error"}
            mock_templates.TemplateResponse.return_value = HTMLResponse(
                content="<html>500</html>", status_code=500
            )

            result = render_error_page(mock_request, "tenant-123", exc)

            assert isinstance(result, HTMLResponse)
            mock_context.assert_called_once_with(
                mock_request,
                "tenant-123",
                error_title="Error",
                error_message="Something went wrong",
                error_code="internal_error",
            )
            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][0] == "error.html"
            assert call_args[1]["status_code"] == 500


def test_render_error_page_passes_context_to_template():
    """Test that render_error_page passes correct context to template."""
    from utils.service_errors import render_error_page

    mock_request = MagicMock(spec=Request)
    exc = NotFoundError(message="User not found", code="user_not_found")

    with patch("utils.service_errors.get_template_context") as mock_context:
        with patch("utils.service_errors.templates") as mock_templates:
            expected_context = {
                "request": mock_request,
                "tenant_id": "tenant-123",
                "error_title": "Not Found",
                "error_message": "User not found",
                "error_code": "user_not_found",
            }
            mock_context.return_value = expected_context
            mock_templates.TemplateResponse.return_value = HTMLResponse(
                content="<html>404</html>", status_code=404
            )

            render_error_page(mock_request, "tenant-123", exc)

            # Verify context was passed to template
            call_args = mock_templates.TemplateResponse.call_args
            assert call_args[0][1] == expected_context
