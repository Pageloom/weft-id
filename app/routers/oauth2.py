"""OAuth2 authorization and token endpoints."""

from typing import Annotated

import oauth2
import services.oauth2 as oauth2_service
from dependencies import get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from middleware.csrf import make_csrf_token_func
from schemas.oauth2 import TokenErrorResponse, TokenResponse

router = APIRouter(prefix="/oauth2", tags=["oauth2"], include_in_schema=False)
templates = Jinja2Templates(directory="app/templates")


# ============================================================================
# Authorization Endpoints (GET/POST /oauth2/authorize)
# ============================================================================


@router.get("/authorize", response_class=HTMLResponse)
def authorize_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    client_id: str,
    redirect_uri: str,
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
):
    """
    OAuth2 authorization endpoint - show authorization page.

    User must be logged in (session cookie) to authorize a client.

    Query Parameters:
        client_id: OAuth2 client ID
        redirect_uri: Redirect URI for authorization code
        state: Optional state parameter
        code_challenge: Optional PKCE code challenge
        code_challenge_method: Optional PKCE challenge method (S256 or plain)
    """
    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid client_id",
                "error_description": "The client_id provided is not registered.",
                "nav": {},
            },
        )

    # Verify client type is 'normal' (authorization code flow only)
    if client["client_type"] != "normal":
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Unauthorized client",
                "error_description": "This client is not authorized for this flow.",
                "nav": {},
            },
        )

    # Verify redirect_uri matches exactly
    if redirect_uri not in (client["redirect_uris"] or []):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid redirect_uri",
                "error_description": "The redirect_uri does not match registered URIs.",
                "nav": {},
            },
        )

    # Verify PKCE parameters if provided
    if code_challenge and code_challenge_method not in ("S256", "plain"):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid request",
                "error_description": "Invalid code_challenge_method. Must be S256 or plain.",
                "nav": {},
            },
        )

    # Show authorization page
    return templates.TemplateResponse(
        request,
        "oauth2_authorize.html",
        {
            "client": client,
            "user": user,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
        },
    )


@router.post("/authorize")
def authorize_grant(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    action: Annotated[str, Form()],
    state: Annotated[str | None, Form()] = None,
    code_challenge: Annotated[str | None, Form()] = None,
    code_challenge_method: Annotated[str | None, Form()] = None,
):
    """
    OAuth2 authorization endpoint - handle allow/deny.

    User submits form to allow or deny authorization.

    Form Data:
        client_id: OAuth2 client ID
        redirect_uri: Redirect URI for authorization code
        action: "allow" or "deny"
        state: Optional state parameter
        code_challenge: Optional PKCE code challenge
        code_challenge_method: Optional PKCE challenge method
    """
    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client or client["client_type"] != "normal":
        # Invalid client, redirect with error
        return RedirectResponse(
            url=f"{redirect_uri}?error=unauthorized_client" + (f"&state={state}" if state else ""),
            status_code=303,
        )

    # Verify redirect_uri matches
    if redirect_uri not in (client["redirect_uris"] or []):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid redirect_uri",
                "error_description": "The redirect_uri does not match registered URIs.",
                "nav": {},
            },
        )

    # Handle denial
    if action == "deny":
        return RedirectResponse(
            url=f"{redirect_uri}?error=access_denied" + (f"&state={state}" if state else ""),
            status_code=303,
        )

    # Handle approval - create authorization code
    if action == "allow":
        code = oauth2_service.create_authorization_code(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=user["id"],
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # Redirect with authorization code
        return RedirectResponse(
            url=f"{redirect_uri}?code={code}" + (f"&state={state}" if state else ""),
            status_code=303,
        )

    # Invalid action
    return RedirectResponse(
        url=f"{redirect_uri}?error=invalid_request" + (f"&state={state}" if state else ""),
        status_code=303,
    )


# ============================================================================
# Token Endpoint (POST /oauth2/token)
# ============================================================================


@router.post("/token", response_model=TokenResponse, responses={400: {"model": TokenErrorResponse}})
def token_endpoint(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
):
    """
    OAuth2 token endpoint - exchange authorization code or refresh token for access token.

    Supports three grant types:
    1. authorization_code - Exchange auth code for access + refresh tokens
    2. refresh_token - Refresh access token using refresh token
    3. client_credentials - Get access token using client credentials (B2B)

    Form Data:
        grant_type: "authorization_code", "refresh_token", or "client_credentials"
        client_id: OAuth2 client ID
        client_secret: OAuth2 client secret
        code: Authorization code (for authorization_code grant)
        redirect_uri: Redirect URI (for authorization_code grant, must match)
        code_verifier: PKCE code verifier (if PKCE was used)
        refresh_token: Refresh token (for refresh_token grant)
    """
    # Get and validate client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            },
        )

    # Verify client secret
    if not oauth2.verify_token_hash(client_secret, client["client_secret_hash"]):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            },
        )

    # ========================================================================
    # Grant Type: authorization_code
    # ========================================================================
    if grant_type == "authorization_code":
        # Validate client type
        if client["client_type"] != "normal":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unauthorized_client",
                    "error_description": "Client is not authorized for this grant type",
                },
            )

        # Validate required parameters
        if not code or not redirect_uri:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": "Missing required parameter: code or redirect_uri",
                },
            )

        # Validate and consume authorization code
        code_data = oauth2_service.validate_and_consume_code(
            tenant_id=tenant_id,
            code=code,
            client_id=client["id"],
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        if not code_data:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired authorization code",
                },
            )

        # Create refresh token
        refresh_token_str, refresh_token_id = oauth2_service.create_refresh_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=code_data["user_id"],
        )

        # Create access token
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=code_data["user_id"],
            parent_token_id=refresh_token_id,
        )

        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=int(oauth2.ACCESS_TOKEN_EXPIRY.total_seconds()),
            refresh_token=refresh_token_str,
        )

    # ========================================================================
    # Grant Type: refresh_token
    # ========================================================================
    elif grant_type == "refresh_token":
        # Validate required parameters
        if not refresh_token:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": "Missing required parameter: refresh_token",
                },
            )

        # Validate refresh token
        token_data = oauth2_service.validate_refresh_token(
            tenant_id=tenant_id,
            token=refresh_token,
            client_id=client["id"],
        )

        if not token_data:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired refresh token",
                },
            )

        # Create new access token (linked to refresh token)
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=token_data["user_id"],
            parent_token_id=token_data["id"],
        )

        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=int(oauth2.ACCESS_TOKEN_EXPIRY.total_seconds()),
            refresh_token=None,  # Don't return refresh token on refresh
        )

    # ========================================================================
    # Grant Type: client_credentials
    # ========================================================================
    elif grant_type == "client_credentials":
        # Validate client type
        if client["client_type"] != "b2b":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unauthorized_client",
                    "error_description": "Client is not authorized for this grant type",
                },
            )

        # Get service user ID
        service_user_id = client["service_user_id"]
        if not service_user_id:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "server_error",
                    "error_description": "Client configuration error: missing service user",
                },
            )

        # Create access token (24h expiry, no refresh token)
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=service_user_id,
            is_client_credentials=True,
        )

        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=int(oauth2.CLIENT_CREDENTIALS_TOKEN_EXPIRY.total_seconds()),
            refresh_token=None,  # No refresh token for client credentials
        )

    # ========================================================================
    # Unsupported grant type
    # ========================================================================
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_grant_type",
                "error_description": f"Grant type '{grant_type}' is not supported",
            },
        )
