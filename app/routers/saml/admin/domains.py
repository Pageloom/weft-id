"""Admin endpoints for domain binding to IdPs."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from services import saml as saml_service
from services.exceptions import NotFoundError, ServiceError

router = APIRouter()


@router.post(
    "/admin/settings/identity-providers/{idp_id}/bind-domain",
    dependencies=[Depends(require_super_admin)],
)
def bind_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    domain_id: Annotated[str, Form()],
):
    """Bind a privileged domain to this IdP."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.bind_domain_to_idp(requesting_user, idp_id, domain_id)
    except NotFoundError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/admin/settings/identity-providers/{idp_id}?success=domain_bound",
        status_code=303,
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/unbind-domain/{domain_id}",
    dependencies=[Depends(require_super_admin)],
)
def unbind_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    domain_id: str,
):
    """Unbind a domain from this IdP."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.unbind_domain_from_idp(requesting_user, domain_id)
    except NotFoundError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/admin/settings/identity-providers/{idp_id}?success=domain_unbound",
        status_code=303,
    )
