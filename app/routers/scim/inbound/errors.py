"""SCIM-specific exception classes and FastAPI handlers.

Any code path under `/scim/v2/inbound/...` that needs to bail out
with a SCIM-shaped error response raises `ScimErrorException` (with
the HTTP status and the human-readable detail). The handler
registered in `main.py` translates that to the SCIM 2.0 Error
envelope (`schemas`, `status`, `scimType`, `detail`) and sets the
right content type.

Authentication failures use the same shape every time: same status
(401), same body (`"Authentication required"`, no scimType), so the
caller cannot distinguish "no token" from "wrong tenant for this
IdP". This is deliberate -- otherwise an unauthenticated attacker
could probe for which tenants own which IdP ids.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from utils.scim_responses import scim_error_response


class ScimErrorException(Exception):  # noqa: N818 -- name avoids clash with schemas.scim.ScimError
    """Bail out with a SCIM-shaped error response.

    Attributes:
        status_code: HTTP status (401, 403, 404, 429, 500).
        detail: Human-readable description.
        scim_type: Optional machine-readable error class
            (e.g. `invalidFilter`, `mutability`). Set for 400-family.
        headers: Optional extra HTTP headers (e.g. `Retry-After` for
            rate limits, `WWW-Authenticate` for 401s).
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        scim_type: str | None = None,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.scim_type = scim_type
        self.headers = headers


def _handle_scim_error(_request: Request, exc: ScimErrorException) -> JSONResponse:
    return scim_error_response(
        exc.status_code,
        exc.detail,
        scim_type=exc.scim_type,
        headers=exc.headers,
    )


def register_scim_exception_handlers(app: FastAPI) -> None:
    """Register the SCIM error handler on the FastAPI app."""
    app.add_exception_handler(ScimErrorException, _handle_scim_error)  # type: ignore[arg-type]
