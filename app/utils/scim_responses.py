"""Helpers for building SCIM 2.0 wire responses.

The SCIM `content-type` is `application/scim+json` (RFC 7644 §3.1.1).
Most clients accept `application/json` too, but for spec-correctness
we set the SCIM media type on every response we generate.

The error envelope deliberately produces the same shape for every
authentication failure (no header, bad token, revoked, wrong tenant
for the idp_id). The detail string is intentionally generic --
"Authentication required" -- to avoid leaking tenancy information to
an unauthenticated caller.
"""

from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse
from schemas.scim import ERROR_SCHEMA

SCIM_CONTENT_TYPE = "application/scim+json"


def scim_error_response(
    status_code: int,
    detail: str,
    *,
    scim_type: str | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Return a SCIM 2.0 Error response (RFC 7644 §3.12).

    `status` in the body is the HTTP status as a string per the spec.
    `scimType` is set for 400-family errors that benefit from a
    machine-readable error class; pass None for everything else.
    """
    body: dict[str, Any] = {
        "schemas": [ERROR_SCHEMA],
        "status": str(status_code),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type

    response_headers = {"Content-Type": SCIM_CONTENT_TYPE}
    if headers:
        response_headers.update(headers)

    return JSONResponse(
        status_code=status_code,
        content=body,
        headers=response_headers,
    )


def scim_json_response(
    body: dict[str, Any] | list[Any],
    *,
    status_code: int = 200,
    location: str | None = None,
) -> JSONResponse:
    """Return a SCIM 2.0 success response with the right content type.

    `location` (when provided) is set on the HTTP `Location` header --
    useful for POST 201 responses.
    """
    headers = {"Content-Type": SCIM_CONTENT_TYPE}
    if location:
        headers["Location"] = location
    return JSONResponse(status_code=status_code, content=body, headers=headers)
