"""Request objects at the authorization endpoint (OpenID Connect Core 1.0
section 6, RFC 9101).

A relying party may send its authorization request parameters inside a JWT it
signed, by value (``request``) or by reference (``request_uri``, a URL WeftID
fetches). :func:`resolve_request_object` verifies the object and returns the
parameters it carries; the router merges them over the query (Core 6.3.3: a
value in the object wins).

Rules:

- Only signed objects are accepted: RS256, PS256 or ES256 with a key from the
  client's ``jwks`` / ``jwks_uri`` (the client's registered
  ``request_object_signing_alg`` when it has one). Unsigned objects
  (``alg=none``) are refused; discovery does not list ``none``.
- ``iss``, when present, must be the client_id; ``aud``, when present, must
  name the issuer; ``exp`` / ``nbf`` are enforced when present.
- ``client_id`` and ``response_type`` inside the object must match the query
  values when both are sent (Core 6.1).
- A ``request_uri`` must be one the client registered (``request_uris``,
  compared without the fragment; Core 6.2, ``require_request_uri_registration``)
  and is fetched through the SSRF guard with a size cap.

There is no user and nothing is written: no audit event. A refusal is logged at
INFO with the reason.
"""

import logging

from services import oauth2_client_auth
from services.exceptions import ValidationError
from utils.safe_http import build_safe_client

logger = logging.getLogger(__name__)

SIGNING_ALG_VALUES_SUPPORTED = oauth2_client_auth.SIGNING_ALG_VALUES_SUPPORTED

# Error codes (OpenID Connect Core 1.0 section 6.4, RFC 6749 4.1.2.1).
INVALID_REQUEST = "invalid_request"
INVALID_REQUEST_OBJECT = "invalid_request_object"
INVALID_REQUEST_URI = "invalid_request_uri"

# The authorization parameters a request object may carry, with the same
# length bounds the endpoint applies to query and form values.
PARAMETER_MAX_LENGTHS: dict[str, int] = {
    "client_id": 255,
    "redirect_uri": 2048,
    "response_type": 50,
    "state": 2048,
    "scope": 500,
    "nonce": 512,
    "code_challenge": 255,
    "code_challenge_method": 50,
    "prompt": 50,
    "max_age": 20,
    "login_hint": 320,
    "id_token_hint": 8192,
    "response_mode": 50,
    "display": 50,
    "ui_locales": 255,
    "claims_locales": 255,
    "acr_values": 255,
}

# A fetched object is bounded like a jwks_uri document.
MAX_FETCHED_REQUEST_OBJECT_BYTES = 16384
_FETCH_TIMEOUT_SECONDS = 5.0

# The OIDC conformance suite serves request objects from a docker service on
# the dev network with a self-signed certificate. Dev only, as for jwks_uri.
_DEV_HOSTNAME_ALLOWLIST = frozenset({"localhost.emobix.co.uk"})


class _RefusedError(Exception):
    """Internal: why a request object was refused (logged, never returned)."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code


_MESSAGES = {
    INVALID_REQUEST: "Send either request or request_uri, not both.",
    INVALID_REQUEST_OBJECT: "The request object could not be verified.",
    INVALID_REQUEST_URI: "The request_uri is not registered or could not be retrieved.",
}


def registered_request_uris(client: dict) -> list[str]:
    """The ``request_uris`` the client registered (RFC 7591 metadata)."""
    value = (client.get("registration_metadata") or {}).get("request_uris")
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _without_fragment(uri: str) -> str:
    return uri.split("#", 1)[0]


def _fetch(request_uri: str) -> str:
    """Fetch a request object by reference through the SSRF guard."""
    http = build_safe_client(
        timeout=_FETCH_TIMEOUT_SECONDS,
        dev_hostname_allowlist=_DEV_HOSTNAME_ALLOWLIST,
        dev_skip_tls_verify=True,
        dev_base_domain_rewrite=True,
    )
    try:
        with http, http.stream("GET", _without_fragment(request_uri)) as response:
            if response.status_code != 200:
                raise _RefusedError(
                    INVALID_REQUEST_URI, f"request_uri returned HTTP {response.status_code}"
                )
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_FETCHED_REQUEST_OBJECT_BYTES:
                    raise _RefusedError(INVALID_REQUEST_URI, "request_uri document is too large")
    except _RefusedError:
        raise
    except Exception as exc:  # noqa: BLE001 - any transport failure is a refusal
        raise _RefusedError(
            INVALID_REQUEST_URI, f"request_uri fetch failed: {type(exc).__name__}"
        ) from exc
    try:
        return body.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _RefusedError(INVALID_REQUEST_OBJECT, "request_uri document is not a JWT") from exc


def _parameters(claims: dict, *, issuer: str, client: dict) -> dict[str, str]:
    """Check the envelope claims and extract the authorization parameters."""
    if "iss" in claims and claims["iss"] != client["client_id"]:
        raise _RefusedError(INVALID_REQUEST_OBJECT, "iss is not the client_id")
    if "aud" in claims:
        aud = claims["aud"]
        audiences = aud if isinstance(aud, list) else [aud]
        if issuer.rstrip("/") not in [a.rstrip("/") for a in audiences if isinstance(a, str)]:
            raise _RefusedError(INVALID_REQUEST_OBJECT, "aud does not name the issuer")

    params: dict[str, str] = {}
    for name, max_length in PARAMETER_MAX_LENGTHS.items():
        value = claims.get(name)
        if value is None:
            continue
        # max_age is a JSON number in a request object (Core 3.1.2.1).
        if name == "max_age" and isinstance(value, int) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str) or len(value) > max_length:
            raise _RefusedError(INVALID_REQUEST_OBJECT, f"{name} is not a valid string")
        params[name] = value
    return params


def _resolve(
    tenant_id: str,
    client: dict,
    *,
    request_object: str | None,
    request_uri: str | None,
    issuer: str,
    query_client_id: str | None,
    query_response_type: str | None,
) -> dict[str, str]:
    if request_object is not None and request_uri is not None:
        raise _RefusedError(INVALID_REQUEST, "both request and request_uri")

    if request_uri is not None:
        registered = {_without_fragment(u) for u in registered_request_uris(client)}
        if _without_fragment(request_uri) not in registered:
            raise _RefusedError(INVALID_REQUEST_URI, "request_uri is not registered")
        request_object = _fetch(request_uri)
    if not request_object:
        raise _RefusedError(INVALID_REQUEST_OBJECT, "empty request object")

    if client.get("jwks") is None and not client.get("jwks_uri"):
        raise _RefusedError(INVALID_REQUEST_OBJECT, "client has no keys")
    registered_alg = (client.get("registration_metadata") or {}).get("request_object_signing_alg")
    allowed = (registered_alg,) if registered_alg else SIGNING_ALG_VALUES_SUPPORTED
    try:
        claims = oauth2_client_auth.verify_client_signed_jwt(
            tenant_id, client, request_object, allowed_algs=allowed
        )
    except ValueError as exc:
        raise _RefusedError(INVALID_REQUEST_OBJECT, str(exc)) from None

    params = _parameters(claims, issuer=issuer, client=client)
    must_match = (("client_id", query_client_id), ("response_type", query_response_type))
    for name, query_value in must_match:
        if name in params and query_value is not None and params[name] != query_value:
            raise _RefusedError(INVALID_REQUEST_OBJECT, f"{name} does not match the query")
    return params


def resolve_request_object(
    tenant_id: str,
    client: dict,
    *,
    request_object: str | None,
    request_uri: str | None,
    issuer: str,
    query_client_id: str | None,
    query_response_type: str | None,
) -> dict[str, str]:
    """Verify a request object and return the authorization parameters in it.

    Authorization: none -- the client was identified by its client_id and the
    object's signature is what authenticates its contents.

    Args:
        tenant_id: Tenant ID
        client: The client named by the query ``client_id`` (active, confidential)
        request_object: The ``request`` parameter, if sent
        request_uri: The ``request_uri`` parameter, if sent
        issuer: The tenant issuer (accepted ``aud``)
        query_client_id / query_response_type: The query values (must match)

    Returns:
        Parameter name -> value for every authorization parameter in the object

    Raises:
        ValidationError: ``code`` is the OAuth2 error to answer with
            (``invalid_request``, ``invalid_request_object``,
            ``invalid_request_uri``)
    """
    try:
        return _resolve(
            tenant_id,
            client,
            request_object=request_object,
            request_uri=request_uri,
            issuer=issuer,
            query_client_id=query_client_id,
            query_response_type=query_response_type,
        )
    except _RefusedError as exc:
        logger.info("Request object refused for client %s: %s", client.get("client_id"), exc)
        raise ValidationError(message=_MESSAGES[exc.code], code=exc.code) from None
