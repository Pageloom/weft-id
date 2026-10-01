"""Dynamic client registration endpoints (RFC 7591, RFC 7592).

- ``POST /oauth2/register``: register a client. Closed (404) unless the tenant
  turned registration on; an initial access token is required as a bearer
  token when the policy says so.
- ``GET|PUT|DELETE /oauth2/register/{client_id}``: the client configuration
  endpoint, authorized by the client's registration access token.

Server to server: no session, no CSRF (the middleware exempts these paths).
Request and response bodies are JSON. Errors are RFC 7591 section 3.2.2
objects (``error``, ``error_description``); a bad bearer token is a 401 with a
``WWW-Authenticate: Bearer`` challenge (RFC 6750 section 3).
"""

import json
import logging
from typing import Annotated

import services.oauth2_registration as registration_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import JSONResponse, Response
from services.exceptions import (
    NotFoundError,
    RateLimitError,
    UnauthorizedError,
    ValidationError,
)
from utils.ratelimit import HOUR, ratelimit
from utils.request_metadata import extract_remote_address
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oauth2", tags=["oauth2"], include_in_schema=False)

# Registration requests are small; anything bigger is refused unread.
MAX_BODY_BYTES = 65536

# Registrations per client IP per hour. Generous enough for the conformance
# suite (one registration per test module) and any real onboarding flow.
REGISTRATION_RATE_LIMIT = 100

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}

_BEARER_MAX_LENGTH = 255


def _error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    headers = dict(_NO_STORE)
    if status_code == 401:
        headers["WWW-Authenticate"] = f'Bearer error="{error}"'
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=headers,
    )


def _not_found() -> JSONResponse:
    return JSONResponse({"detail": "Not Found"}, status_code=404, headers=_NO_STORE)


def _bearer_token(request: Request) -> str | None:
    """The bearer token from the Authorization header, or None.

    An over-long value is treated as present but unusable (it cannot match any
    stored token), so it is reported as invalid rather than missing.
    """
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()[: _BEARER_MAX_LENGTH + 1]


async def _read_json_body(request: Request) -> bytes | None:
    """The raw request body, or None when it is larger than MAX_BODY_BYTES."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    body = await request.body()
    return body if len(body) <= MAX_BODY_BYTES else None


def _parse_metadata(body: bytes | None) -> dict | JSONResponse:
    if body is None:
        return _error("invalid_client_metadata", "The request body is too large.")
    try:
        metadata = json.loads(body)
    except ValueError, UnicodeDecodeError:
        return _error("invalid_client_metadata", "The request body must be a JSON object.")
    if not isinstance(metadata, dict):
        return _error("invalid_client_metadata", "The request body must be a JSON object.")
    return metadata


@router.post("/register")
def register_client(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    body: Annotated[bytes | None, Depends(_read_json_body)],
) -> Response:
    """
    OAuth 2.0 Dynamic Client Registration (RFC 7591, OpenID Connect Dynamic
    Client Registration 1.0).

    Returns 404 while the tenant's registration policy is ``off``. Under
    ``token_required`` the request must carry an initial access token as
    ``Authorization: Bearer <token>``; under ``open`` no token is needed (a
    presented token must still be valid). Rate-limited per client IP.

    Request body (JSON client metadata):
        redirect_uris: Required. Absolute https URIs without a fragment; a
            ``native`` client may also use http on a loopback address
        client_name: Display name (max 255; defaults to the redirect host)
        application_type: "web" (default) or "native"
        response_types: ["code"] (the only supported value)
        grant_types: "authorization_code" (required) and optionally
            "refresh_token"
        token_endpoint_auth_method: "client_secret_basic" (default) or
            "client_secret_post"
        id_token_signed_response_alg: "RS256" only
        subject_type: "public" only
        logo_uri, client_uri, policy_uri, tos_uri: https URIs. The logo and
            the policy and terms links are shown on the consent page
        contacts: Up to 10 strings
        jwks, jwks_uri: The client's keys (stored; not mutually combinable)
        post_logout_redirect_uris, frontchannel_logout_uri,
        frontchannel_logout_session_required, backchannel_logout_uri,
        backchannel_logout_session_required: As for an admin-created client
        Encryption, userinfo signing, request-object, and pairwise metadata
        are rejected with invalid_client_metadata. Unknown metadata is ignored.

    Returns:
        201 with the registered metadata plus ``client_id``,
        ``client_secret``, ``client_secret_expires_at`` (0),
        ``client_id_issued_at``, ``registration_access_token``, and
        ``registration_client_uri``. Errors: 400 ``invalid_redirect_uri`` /
        ``invalid_client_metadata``, 401 ``invalid_token``, 404, 429.
    """
    try:
        ratelimit.prevent(
            "oauth2_register:tenant:{tenant_id}:ip:{ip}",
            limit=REGISTRATION_RATE_LIMIT,
            timespan=HOUR,
            tenant_id=tenant_id,
            ip=extract_remote_address(request) or "unknown",
        )
    except RateLimitError as exc:
        response = _error("too_many_requests", exc.message, status_code=429)
        response.headers["Retry-After"] = str(exc.retry_after)
        return response

    if not registration_service.is_registration_enabled(tenant_id):
        return _not_found()

    metadata = _parse_metadata(body)
    if isinstance(metadata, JSONResponse):
        return metadata

    try:
        result = registration_service.register_client(
            tenant_id,
            metadata,
            initial_access_token=_bearer_token(request),
            base_url=tenant_base_url(request),
        )
    except NotFoundError:
        return _not_found()
    except UnauthorizedError as exc:
        return _error("invalid_token", exc.message, status_code=401)
    except ValidationError as exc:
        return _error(exc.code, exc.message)

    return JSONResponse(result, status_code=201, headers=_NO_STORE)


def _authenticated_client(request: Request, tenant_id: str, client_id: str) -> dict | Response:
    try:
        return registration_service.authenticate_registration(
            tenant_id, client_id, _bearer_token(request)
        )
    except UnauthorizedError as exc:
        return _error("invalid_token", exc.message, status_code=401)


ClientIdPath = Annotated[str, Path(max_length=255)]


@router.get("/register/{client_id}")
def read_client_configuration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    client_id: ClientIdPath,
) -> Response:
    """
    Client configuration endpoint, read (RFC 7592 section 2.1).

    Requires the client's registration access token as
    ``Authorization: Bearer <token>``. Works whatever the current registration
    policy, as do update and delete.

    Path Parameters:
        client_id: The registered client's client_id

    Returns:
        200 with the registered metadata (no ``client_secret`` or
        ``registration_access_token``; neither is stored in a readable form).
        401 ``invalid_token`` for a missing or wrong token, an unknown or
        deactivated client, or one an admin created.
    """
    client = _authenticated_client(request, tenant_id, client_id)
    if isinstance(client, Response):
        return client
    body = registration_service.read_client_configuration(client, tenant_base_url(request))
    return JSONResponse(body, headers=_NO_STORE)


@router.put("/register/{client_id}")
def update_client_configuration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    client_id: ClientIdPath,
    body: Annotated[bytes | None, Depends(_read_json_body)],
) -> Response:
    """
    Client configuration endpoint, update (RFC 7592 section 2.2).

    A full replacement: metadata left out returns to its default. The body must
    carry ``client_id`` (matching the path); a ``client_secret``, if sent, must
    be the current one. Accepts the same metadata as registration. Credentials,
    access settings and the registration access token are unchanged.

    Path Parameters:
        client_id: The registered client's client_id

    Returns:
        200 with the registered metadata. 400 ``invalid_redirect_uri`` /
        ``invalid_client_metadata``, 401 ``invalid_token``.
    """
    client = _authenticated_client(request, tenant_id, client_id)
    if isinstance(client, Response):
        return client
    metadata = _parse_metadata(body)
    if isinstance(metadata, JSONResponse):
        return metadata
    try:
        result = registration_service.update_client_configuration(
            tenant_id, client, metadata, tenant_base_url(request)
        )
    except UnauthorizedError as exc:
        return _error("invalid_token", exc.message, status_code=401)
    except ValidationError as exc:
        return _error(exc.code, exc.message)
    return JSONResponse(result, headers=_NO_STORE)


@router.delete("/register/{client_id}")
def delete_client_configuration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    client_id: ClientIdPath,
) -> Response:
    """
    Client configuration endpoint, delete (RFC 7592 section 2.3).

    Deletes the client with its tokens, codes and consent grants. The
    registration access token stops working.

    Path Parameters:
        client_id: The registered client's client_id

    Returns:
        204. 401 ``invalid_token``.
    """
    client = _authenticated_client(request, tenant_id, client_id)
    if isinstance(client, Response):
        return client
    registration_service.delete_client_configuration(tenant_id, client)
    return Response(status_code=204, headers=_NO_STORE)
