"""Dev-only router for E2E test support.

This router is only registered when IS_DEV=true. It provides an instant
login endpoint that bypasses the full authentication flow, allowing E2E
tests to authenticate quickly via a single GET request.
"""

from database.users.core import get_user_by_email
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from utils.session import regenerate_session

router = APIRouter(prefix="/dev", tags=["dev"])


@router.get("/login")
async def dev_login(request: Request, email: str):
    """Instantly log in as the user with the given email.

    Sets a session cookie and redirects to /dashboard. Only available
    when IS_DEV=true.
    """
    tenant_id = get_tenant_id_from_request(request)
    user = get_user_by_email(tenant_id, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    regenerate_session(request, str(user["user_id"]), max_age=30 * 24 * 3600)
    return RedirectResponse(url="/dashboard", status_code=303)
