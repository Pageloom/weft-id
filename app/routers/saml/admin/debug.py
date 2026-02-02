"""Admin endpoints for SAML debugging and connection testing."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from schemas.saml import SAMLTestResult
from services import saml as saml_service
from services.exceptions import NotFoundError, ServiceError
from utils.template_context import get_template_context

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get(
    "/admin/settings/identity-providers/debug",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def saml_debug_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List recent SAML authentication failures for debugging."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    entries = saml_service.list_saml_debug_entries(requesting_user, limit=50)

    return templates.TemplateResponse(
        request,
        "saml_debug_list.html",
        get_template_context(
            request,
            tenant_id,
            entries=entries,
        ),
    )


@router.get(
    "/admin/settings/identity-providers/debug/{entry_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def saml_debug_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    entry_id: str,
):
    """View detailed SAML debug entry with XML."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        entry = saml_service.get_saml_debug_entry(requesting_user, entry_id)
    except NotFoundError:
        return RedirectResponse(
            url="/admin/settings/identity-providers/debug?error=entry_not_found",
            status_code=303,
        )

    return templates.TemplateResponse(
        request,
        "saml_debug_detail.html",
        get_template_context(
            request,
            tenant_id,
            entry=entry,
        ),
    )


@router.get(
    "/admin/settings/identity-providers/{idp_id}/test",
    dependencies=[Depends(require_super_admin)],
)
def test_idp_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """
    Initiate SAML test flow.

    Redirects to IdP with test=true in RelayState to distinguish from real logins.
    Opens in a new window (frontend handles this).
    """
    # Authorization handled by require_super_admin dependency

    # Use special RelayState to indicate test mode
    relay_state = f"__test__:{idp_id}"

    try:
        redirect_url, request_id = saml_service.build_authn_request(tenant_id, idp_id, relay_state)

        # Store test context in session
        request.session["saml_test_request_id"] = request_id
        request.session["saml_test_idp_id"] = idp_id

        return RedirectResponse(url=redirect_url, status_code=303)

    except NotFoundError:
        return templates.TemplateResponse(
            request,
            "saml_test_result.html",
            get_template_context(
                request,
                tenant_id,
                test_result=SAMLTestResult(
                    success=False,
                    error_type="idp_not_found",
                    error_detail="Identity provider not found",
                ),
                idp_id=idp_id,
                idp_name="Unknown",
            ),
        )
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_test_result.html",
            get_template_context(
                request,
                tenant_id,
                test_result=SAMLTestResult(
                    success=False,
                    error_type="configuration_error",
                    error_detail=str(e),
                ),
                idp_id=idp_id,
                idp_name="Unknown",
            ),
        )
