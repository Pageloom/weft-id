"""Account-level passkey (WebAuthn) routes.

HTML/form routes for listing, registering, renaming, and deleting passkeys.
All routes require authentication via ``require_current_user`` and are scoped
to the requesting user. Cross-user admin actions live in a separate admin
router (added in a later iteration).
"""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from schemas.webauthn import CompleteRegistrationRequest
from services import webauthn as webauthn_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/account/passkeys",
    tags=["account"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.get("", response_class=HTMLResponse)
def passkeys_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Render the user's passkey list."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        passkeys = webauthn_service.list_credentials(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        request,
        "settings_passkeys.html",
        get_template_context(
            request,
            tenant_id,
            passkeys=passkeys,
        ),
    )


@router.post("/begin-registration")
def begin_registration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Return ``PublicKeyCredentialCreationOptions`` and stash the challenge."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        result = webauthn_service.begin_registration(requesting_user, request)
    except ValidationError as exc:
        return JSONResponse({"error": exc.message, "code": exc.code}, status_code=400)
    except ServiceError as exc:
        return JSONResponse({"error": exc.message, "code": exc.code}, status_code=400)

    return JSONResponse({"publicKey": result.public_key})


@router.post("/complete-registration")
async def complete_registration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Verify a registration response, persist the credential, and return the
    resulting passkey plus any one-time backup codes.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON body", "code": "invalid_json"},
            status_code=400,
        )

    try:
        payload = CompleteRegistrationRequest.model_validate(body)
    except Exception as exc:
        return JSONResponse(
            {"error": "Invalid request payload", "code": "invalid_payload", "details": str(exc)},
            status_code=400,
        )

    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        result = webauthn_service.complete_registration(requesting_user, request, payload)
    except ValidationError as exc:
        return JSONResponse({"error": exc.message, "code": exc.code}, status_code=400)
    except ServiceError as exc:
        return JSONResponse({"error": exc.message, "code": exc.code}, status_code=400)

    return JSONResponse(result.model_dump())


@router.post("/{credential_id}/rename")
def rename_passkey(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    credential_id: str,
    name: Annotated[str, Form(max_length=100)],
):
    """Rename a passkey via a standard HTML form post."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        webauthn_service.rename_credential(requesting_user, credential_id, name)
    except NotFoundError:
        return RedirectResponse(url="/account/passkeys?error=not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/account/passkeys?error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/passkeys?success=renamed", status_code=303)


@router.post("/{credential_id}/delete")
def delete_passkey(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    credential_id: str,
):
    """Delete a passkey via a standard HTML form post."""
    requesting_user = build_requesting_user(user, user["tenant_id"], request)
    try:
        webauthn_service.delete_credential(requesting_user, credential_id)
    except NotFoundError:
        return RedirectResponse(url="/account/passkeys?error=not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/passkeys?success=deleted", status_code=303)
