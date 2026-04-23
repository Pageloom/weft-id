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
from fastapi.responses import JSONResponse, RedirectResponse
from schemas.webauthn import CompleteRegistrationRequest
from services import webauthn as webauthn_service
from services.exceptions import NotFoundError, RateLimitError, ServiceError, ValidationError
from utils.ratelimit import MINUTE, ratelimit
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/account/passkeys",
    tags=["account"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.get("")
def passkeys_page():
    """The passkey UI is rendered inline on /account/mfa. This URL is kept as a
    redirect for backwards compatibility with any bookmarked links.
    """
    return RedirectResponse(url="/account/mfa", status_code=303)


@router.post("/begin-registration")
def begin_registration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Return ``PublicKeyCredentialCreationOptions`` and stash the challenge."""
    try:
        ratelimit.prevent(
            "passkey_reg_begin:user:{user_id}",
            limit=10,
            timespan=MINUTE * 5,
            user_id=str(user["id"]),
        )
    except RateLimitError:
        return JSONResponse(
            {"error": "Too many requests", "code": "too_many_requests"}, status_code=429
        )

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
        ratelimit.prevent(
            "passkey_reg_complete:user:{user_id}",
            limit=10,
            timespan=MINUTE * 5,
            user_id=str(user["id"]),
        )
    except RateLimitError:
        return JSONResponse(
            {"error": "Too many requests", "code": "too_many_requests"}, status_code=429
        )

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

    return JSONResponse(result.model_dump(mode="json"))


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
        return RedirectResponse(url="/account/mfa?passkey_error=not_found", status_code=303)
    except ValidationError as exc:
        return RedirectResponse(url=f"/account/mfa?passkey_error={exc.code}", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/mfa?passkey_success=renamed", status_code=303)


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
        return RedirectResponse(url="/account/mfa?passkey_error=not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/mfa?passkey_success=deleted", status_code=303)
