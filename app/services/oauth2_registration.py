"""OpenID Connect Dynamic Client Registration (RFC 7591) and client
configuration management (RFC 7592).

Two kinds of callers:

- **Admins** set the tenant's registration policy and default access, and
  issue and revoke initial access tokens. These functions take a
  ``RequestingUser`` and require the admin role, like the rest of OAuth2 app
  management.
- **Clients** register themselves and then read, replace, or delete their own
  registration. There is no user: the registration endpoint is authorized by
  the tenant policy (and an initial access token when the policy asks for
  one), the configuration endpoint by the client's registration access token.
  Their audit events use the system actor and name the token in metadata.

A registered client is always a ``normal`` (authorization code) client with
OIDC enabled, never B2B. It starts available to every user or to no one,
per the tenant's ``default_access``. Remembered consent applies as for any
other client; registered clients are never pre-consented.

Metadata policy: values WeftID cannot honour are rejected
(``invalid_client_metadata``) rather than silently changed, so a client never
believes it got something it did not. Metadata WeftID does not understand is
ignored and not echoed (RFC 7591 section 2). Accepted metadata WeftID does not
act on yet (``jwks``, ``jwks_uri``, ``contacts``) is stored and echoed.
"""

import hashlib
import ipaddress
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import database
import oauth2
from schemas.oauth2 import (
    InitialAccessTokenCreate,
    InitialAccessTokenCreated,
    InitialAccessTokenResponse,
    RegistrationSettings,
    RegistrationSettingsUpdate,
)
from services import oauth2 as oauth2_service
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import NotFoundError, UnauthorizedError, ValidationError
from services.types import RequestingUser

logger = logging.getLogger(__name__)

DEFAULT_POLICY = "off"
DEFAULT_ACCESS = "none"

# RFC 7591 section 3.2.2 error codes.
INVALID_REDIRECT_URI = "invalid_redirect_uri"
INVALID_CLIENT_METADATA = "invalid_client_metadata"

# What a registered client may ask for. Anything else is rejected.
SUPPORTED_RESPONSE_TYPES = ("code",)
SUPPORTED_GRANT_TYPES = ("authorization_code", "refresh_token")
SUPPORTED_AUTH_METHODS = ("client_secret_basic", "client_secret_post")
SUPPORTED_APPLICATION_TYPES = ("web", "native")
SUPPORTED_ID_TOKEN_ALG = "RS256"

# Signing and encryption metadata WeftID cannot honour. A request naming any of
# these is refused instead of getting an unsigned or unencrypted response it
# did not ask for.
_UNSUPPORTED_ALG_FIELDS = (
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_signed_response_alg",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "request_object_signing_alg",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "token_endpoint_auth_signing_alg",
)

# Input bounds (the registration endpoint is unauthenticated when open).
MAX_REDIRECT_URIS = 50
MAX_URI_LENGTH = 2048
MAX_NAME_LENGTH = 255
MAX_CONTACTS = 10
MAX_CONTACT_LENGTH = 320
MAX_JWKS_KEYS = 20
MAX_JWKS_BYTES = 32768

_LOOPBACK_HOSTS = ("localhost",)


# =============================================================================
# Admin: registration settings
# =============================================================================


def _settings_row(tenant_id: str) -> dict[str, str]:
    row = database.oauth2.get_registration_settings(tenant_id) or {}
    return {
        "policy": str(row.get("policy") or DEFAULT_POLICY),
        "default_access": str(row.get("default_access") or DEFAULT_ACCESS),
    }


def registration_endpoint_url(base_url: str) -> str:
    """The registration endpoint for a tenant base URL."""
    return f"{base_url.rstrip('/')}/oauth2/register"


def registration_client_uri(base_url: str, client_id: str) -> str:
    """The RFC 7592 client configuration endpoint for one client."""
    return f"{registration_endpoint_url(base_url)}/{client_id}"


def is_registration_enabled(tenant_id: str) -> bool:
    """Whether the registration endpoint is open in any form (for discovery)."""
    return _settings_row(tenant_id)["policy"] != "off"


def get_registration_settings(
    requesting_user: RequestingUser, base_url: str
) -> RegistrationSettings:
    """Read the tenant's dynamic client registration settings.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    row = _settings_row(requesting_user["tenant_id"])
    return RegistrationSettings(
        policy=row["policy"],
        default_access=row["default_access"],
        registration_endpoint=(
            registration_endpoint_url(base_url) if row["policy"] != "off" else None
        ),
    )


def update_registration_settings(
    requesting_user: RequestingUser,
    update: RegistrationSettingsUpdate,
    base_url: str,
) -> RegistrationSettings:
    """Change the registration policy and/or default access.

    Authorization: Requires admin role.
    Logs: oauth2_registration_settings_updated when a value changes.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    current = _settings_row(tenant_id)
    new = {
        "policy": update.policy if update.policy is not None else current["policy"],
        "default_access": (
            update.default_access
            if update.default_access is not None
            else current["default_access"]
        ),
    }
    changes = {
        key: {"old": current[key], "new": new[key]}
        for key in ("policy", "default_access")
        if current[key] != new[key]
    }
    if changes:
        database.oauth2.upsert_registration_settings(
            tenant_id,
            tenant_id,
            policy=new["policy"],
            default_access=new["default_access"],
            updated_by=requesting_user["id"],
        )
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="tenant_settings",
            artifact_id=tenant_id,
            event_type="oauth2_registration_settings_updated",
            metadata={"changes": changes},
        )
    return RegistrationSettings(
        policy=new["policy"],
        default_access=new["default_access"],
        registration_endpoint=(
            registration_endpoint_url(base_url) if new["policy"] != "off" else None
        ),
    )


# =============================================================================
# Admin: initial access tokens
# =============================================================================


def _hash_initial_access_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_status(row: dict, now: datetime) -> str:
    if row.get("revoked_at"):
        return "revoked"
    expires_at = row.get("expires_at")
    if expires_at is not None and expires_at <= now:
        return "expired"
    return "active"


def _token_response(row: dict, now: datetime) -> InitialAccessTokenResponse:
    first = row.get("created_by_first_name")
    last = row.get("created_by_last_name")
    return InitialAccessTokenResponse(
        id=str(row["id"]),
        name=row["name"],
        created_by=str(row["created_by"]) if row.get("created_by") else None,
        created_by_name=" ".join(p for p in (first, last) if p) or None,
        created_at=row["created_at"],
        expires_at=row.get("expires_at"),
        revoked_at=row.get("revoked_at"),
        last_used_at=row.get("last_used_at"),
        registered_client_count=int(row.get("registered_client_count") or 0),
        status=_token_status(row, now),
    )


def list_initial_access_tokens(
    requesting_user: RequestingUser,
) -> list[InitialAccessTokenResponse]:
    """All initial access tokens, newest first (active, expired, and revoked).

    Authorization: Requires admin role.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    now = datetime.now(UTC)
    rows = database.oauth2.list_initial_access_tokens(requesting_user["tenant_id"])
    return [_token_response(row, now) for row in rows]


def create_initial_access_token(
    requesting_user: RequestingUser, data: InitialAccessTokenCreate
) -> InitialAccessTokenCreated:
    """Issue an initial access token. The value is returned once and only its
    SHA-256 digest is stored.

    Authorization: Requires admin role.
    Logs: oauth2_initial_access_token_created.
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    name = data.name.strip()
    if not name:
        raise ValidationError(message="A name is required", code="name_required", field="name")

    token = f"weft-id_iat_{secrets.token_urlsafe(32)}"
    expires_at = (
        datetime.now(UTC) + timedelta(days=data.expires_in_days)
        if data.expires_in_days is not None
        else None
    )
    row = database.oauth2.create_initial_access_token(
        tenant_id,
        tenant_id,
        name=name,
        token_hash=_hash_initial_access_token(token),
        created_by=requesting_user["id"],
        expires_at=expires_at,
    )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_initial_access_token",
        artifact_id=str(row["id"]),
        event_type="oauth2_initial_access_token_created",
        metadata={
            "name": name,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    response = _token_response(row, datetime.now(UTC))
    return InitialAccessTokenCreated(**response.model_dump(), token=token)


def revoke_initial_access_token(
    requesting_user: RequestingUser, token_id: str
) -> InitialAccessTokenResponse:
    """Revoke an initial access token. Clients it already registered keep working.

    Authorization: Requires admin role.
    Logs: oauth2_initial_access_token_revoked.

    Raises:
        NotFoundError: No such token, or it is already revoked
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]
    try:
        uuid.UUID(token_id)
    except ValueError:
        row = None
    else:
        row = database.oauth2.revoke_initial_access_token(tenant_id, token_id)
    if row is None:
        raise NotFoundError(
            message="Initial access token not found or already revoked",
            code="initial_access_token_not_found",
        )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_initial_access_token",
        artifact_id=str(row["id"]),
        event_type="oauth2_initial_access_token_revoked",
        metadata={"name": row["name"]},
    )
    return _token_response(row, datetime.now(UTC))


# =============================================================================
# Protocol: metadata validation
# =============================================================================


def _metadata_error(message: str, code: str = INVALID_CLIENT_METADATA) -> ValidationError:
    return ValidationError(message=message, code=code)


def _optional_str(metadata: dict, name: str, max_length: int) -> str | None:
    value = metadata.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > max_length:
        raise _metadata_error(f"{name} must be a string of at most {max_length} characters")
    return value.strip() or None


def _str_list(
    metadata: dict,
    name: str,
    *,
    max_items: int,
    max_length: int,
    code: str = INVALID_CLIENT_METADATA,
) -> list[str] | None:
    value = metadata.get(name)
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or len(value) > max_items
        or not all(isinstance(v, str) and len(v) <= max_length for v in value)
    ):
        raise _metadata_error(
            f"{name} must be a list of at most {max_items} strings "
            f"of at most {max_length} characters",
            code,
        )
    return value


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_redirect_uris(metadata: dict, application_type: str) -> list[str]:
    uris = _str_list(
        metadata,
        "redirect_uris",
        max_items=MAX_REDIRECT_URIS,
        max_length=MAX_URI_LENGTH,
        code=INVALID_REDIRECT_URI,
    )
    if not uris:
        raise _metadata_error("redirect_uris is required", INVALID_REDIRECT_URI)
    cleaned: list[str] = []
    for uri in uris:
        try:
            parts = urlsplit(uri)
            host = parts.hostname
        except ValueError:
            parts, host = None, None
        valid = (
            parts is not None
            and host
            and not parts.fragment
            and "#" not in uri
            and (
                parts.scheme == "https"
                or (parts.scheme == "http" and application_type == "native" and _is_loopback(host))
            )
        )
        if not valid:
            raise _metadata_error(
                f"Invalid redirect URI: {uri[:200]}. Use an absolute https URI without "
                "a fragment (native clients may also use http on a loopback address).",
                INVALID_REDIRECT_URI,
            )
        if uri not in cleaned:
            cleaned.append(uri)
    return cleaned


def _https_uri(metadata: dict, name: str) -> str | None:
    value = _optional_str(metadata, name, MAX_URI_LENGTH)
    if value is None:
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if parts is None or parts.scheme != "https" or not host or parts.fragment:
        raise _metadata_error(f"{name} must be an absolute https URI without a fragment")
    return value


def _choice_list(
    metadata: dict, name: str, supported: tuple[str, ...], default: list[str]
) -> list[str]:
    values = _str_list(metadata, name, max_items=10, max_length=100)
    if values is None or not values:
        return list(default)
    unsupported = [v for v in values if v not in supported]
    if unsupported:
        raise _metadata_error(
            f"Unsupported {name}: {', '.join(unsupported)[:200]}. Supported: {', '.join(supported)}"
        )
    return list(dict.fromkeys(values))


def _choice(metadata: dict, name: str, supported: tuple[str, ...], default: str) -> str:
    value = metadata.get(name)
    if value is None:
        return default
    if value not in supported:
        raise _metadata_error(f"Unsupported {name}. Supported: {', '.join(supported)}")
    return str(value)


def _validate_jwks(metadata: dict) -> tuple[dict | None, str | None]:
    jwks = metadata.get("jwks")
    jwks_uri = _https_uri(metadata, "jwks_uri")
    if jwks is not None and jwks_uri is not None:
        raise _metadata_error("jwks and jwks_uri must not both be present")
    if jwks is None:
        return None, jwks_uri
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if (
        not isinstance(keys, list)
        or len(keys) > MAX_JWKS_KEYS
        or not all(isinstance(k, dict) for k in keys)
        or len(json.dumps(jwks)) > MAX_JWKS_BYTES
    ):
        raise _metadata_error(f"jwks must be a JSON Web Key Set with at most {MAX_JWKS_KEYS} keys")
    return jwks, None


def validate_client_metadata(metadata: dict) -> dict:
    """Validate a registration request and resolve defaults.

    Returns the accepted registration as a flat dict with every field the
    client will be stored (and echoed) with. Raises ``ValidationError`` whose
    ``code`` is the RFC 7591 error (``invalid_redirect_uri`` or
    ``invalid_client_metadata``).
    """
    if not isinstance(metadata, dict):
        raise _metadata_error("The request body must be a JSON object")

    for name in _UNSUPPORTED_ALG_FIELDS:
        if metadata.get(name) is not None:
            raise _metadata_error(f"{name} is not supported")
    if metadata.get("subject_type") not in (None, "public"):
        raise _metadata_error("Unsupported subject_type. Supported: public")
    id_token_alg = metadata.get("id_token_signed_response_alg")
    if id_token_alg not in (None, SUPPORTED_ID_TOKEN_ALG):
        raise _metadata_error("Unsupported id_token_signed_response_alg. Supported: RS256")

    application_type = _choice(metadata, "application_type", SUPPORTED_APPLICATION_TYPES, "web")
    redirect_uris = _validate_redirect_uris(metadata, application_type)
    response_types = _choice_list(metadata, "response_types", SUPPORTED_RESPONSE_TYPES, ["code"])
    grant_types = _choice_list(
        metadata, "grant_types", SUPPORTED_GRANT_TYPES, ["authorization_code"]
    )
    if "authorization_code" not in grant_types:
        raise _metadata_error("grant_types must include authorization_code")
    auth_method = _choice(
        metadata, "token_endpoint_auth_method", SUPPORTED_AUTH_METHODS, "client_secret_basic"
    )

    client_name = _optional_str(metadata, "client_name", MAX_NAME_LENGTH)
    contacts = _str_list(
        metadata, "contacts", max_items=MAX_CONTACTS, max_length=MAX_CONTACT_LENGTH
    )
    jwks, jwks_uri = _validate_jwks(metadata)

    session_flags = {}
    for name in ("frontchannel_logout_session_required", "backchannel_logout_session_required"):
        value = metadata.get(name, True)
        if not isinstance(value, bool):
            raise _metadata_error(f"{name} must be a boolean")
        session_flags[name] = value

    post_logout = _str_list(
        metadata, "post_logout_redirect_uris", max_items=50, max_length=MAX_URI_LENGTH
    )
    try:
        post_logout_uris = oauth2_service.validate_post_logout_redirect_uris(post_logout or [])
        frontchannel_uri = oauth2_service.validate_frontchannel_logout_uri(
            _optional_str(metadata, "frontchannel_logout_uri", MAX_URI_LENGTH), redirect_uris
        )
        backchannel_uri = oauth2_service.validate_backchannel_logout_uri(
            _optional_str(metadata, "backchannel_logout_uri", MAX_URI_LENGTH)
        )
    except ValidationError as exc:
        raise _metadata_error(exc.message) from exc

    return {
        "client_name": client_name or _fallback_name(redirect_uris),
        "redirect_uris": redirect_uris,
        "post_logout_redirect_uris": post_logout_uris,
        "frontchannel_logout_uri": frontchannel_uri,
        "frontchannel_logout_session_required": session_flags[
            "frontchannel_logout_session_required"
        ],
        "backchannel_logout_uri": backchannel_uri,
        "backchannel_logout_session_required": session_flags["backchannel_logout_session_required"],
        "logo_uri": _https_uri(metadata, "logo_uri"),
        "client_uri": _https_uri(metadata, "client_uri"),
        "policy_uri": _https_uri(metadata, "policy_uri"),
        "tos_uri": _https_uri(metadata, "tos_uri"),
        # Stored as JSON and echoed; nothing outside this module reads them.
        "extra": {
            key: value
            for key, value in {
                "application_type": application_type,
                "response_types": response_types,
                "grant_types": grant_types,
                "token_endpoint_auth_method": auth_method,
                "contacts": contacts,
                "jwks": jwks,
                "jwks_uri": jwks_uri,
            }.items()
            if value is not None
        },
    }


def _fallback_name(redirect_uris: list[str]) -> str:
    host = urlsplit(redirect_uris[0]).hostname or "unknown host"
    return f"Registered client ({host})"[:MAX_NAME_LENGTH]


# =============================================================================
# Protocol: responses
# =============================================================================


def client_configuration(client: dict, base_url: str) -> dict:
    """The registered metadata of a client, as RFC 7591 / RFC 7592 return it."""
    extra = client.get("registration_metadata") or {}
    body: dict = {
        "client_id": client["client_id"],
        "client_id_issued_at": int(client["created_at"].timestamp()),
        "client_name": client["name"],
        "redirect_uris": list(client.get("redirect_uris") or []),
        "application_type": extra.get("application_type", "web"),
        "response_types": extra.get("response_types", ["code"]),
        "grant_types": extra.get("grant_types", ["authorization_code"]),
        "token_endpoint_auth_method": extra.get(
            "token_endpoint_auth_method", "client_secret_basic"
        ),
        "id_token_signed_response_alg": SUPPORTED_ID_TOKEN_ALG,
        "subject_type": "public",
        "registration_client_uri": registration_client_uri(base_url, client["client_id"]),
    }
    for name in ("logo_uri", "client_uri", "policy_uri", "tos_uri"):
        if client.get(name):
            body[name] = client[name]
    for name in ("contacts", "jwks", "jwks_uri"):
        if extra.get(name) is not None:
            body[name] = extra[name]
    if client.get("post_logout_redirect_uris"):
        body["post_logout_redirect_uris"] = list(client["post_logout_redirect_uris"])
    if client.get("frontchannel_logout_uri"):
        body["frontchannel_logout_uri"] = client["frontchannel_logout_uri"]
        body["frontchannel_logout_session_required"] = bool(
            client.get("frontchannel_logout_session_required")
        )
    if client.get("backchannel_logout_uri"):
        body["backchannel_logout_uri"] = client["backchannel_logout_uri"]
        body["backchannel_logout_session_required"] = bool(
            client.get("backchannel_logout_session_required")
        )
    return body


# =============================================================================
# Protocol: registration (RFC 7591)
# =============================================================================


def _authorize_registration(tenant_id: str, initial_access_token: str | None) -> dict | None:
    """Apply the tenant policy. Returns the initial access token row used, if any.

    Raises:
        NotFoundError: the policy is off (the endpoint does not exist)
        UnauthorizedError: a token is required and missing or not valid, or a
            presented token is not valid under the open policy
    """
    policy = _settings_row(tenant_id)["policy"]
    if policy == "off":
        raise NotFoundError(
            message="Dynamic client registration is not enabled",
            code="registration_disabled",
        )
    if initial_access_token is None:
        if policy == "token_required":
            raise UnauthorizedError(message="An initial access token is required")
        return None

    row = database.oauth2.get_initial_access_token_by_hash(
        tenant_id, _hash_initial_access_token(initial_access_token)
    )
    if row is None or _token_status(row, datetime.now(UTC)) != "active":
        raise UnauthorizedError(message="The initial access token is not valid")
    return row


def register_client(
    tenant_id: str,
    metadata: dict,
    *,
    initial_access_token: str | None,
    base_url: str,
) -> dict:
    """Register a client (RFC 7591 section 3).

    Logs: oauth2_client_registered (system actor).

    Returns:
        The registration response: the client configuration plus
        ``client_secret``, ``client_secret_expires_at`` (0, never) and the
        ``registration_access_token``. Both secrets exist only in this value.

    Raises:
        NotFoundError: registration is off
        UnauthorizedError: missing or invalid initial access token
        ValidationError: invalid metadata (``code`` is the RFC 7591 error)
    """
    token_row = _authorize_registration(tenant_id, initial_access_token)
    accepted = validate_client_metadata(metadata)
    registration_access_token = oauth2.generate_opaque_token("weft-id_rat")
    available_to_all = _settings_row(tenant_id)["default_access"] == "all"

    client = database.oauth2.create_registered_client(
        tenant_id,
        tenant_id,
        name=accepted["client_name"],
        redirect_uris=accepted["redirect_uris"],
        post_logout_redirect_uris=accepted["post_logout_redirect_uris"],
        frontchannel_logout_uri=accepted["frontchannel_logout_uri"],
        frontchannel_logout_session_required=accepted["frontchannel_logout_session_required"],
        backchannel_logout_uri=accepted["backchannel_logout_uri"],
        backchannel_logout_session_required=accepted["backchannel_logout_session_required"],
        logo_uri=accepted["logo_uri"],
        client_uri=accepted["client_uri"],
        policy_uri=accepted["policy_uri"],
        tos_uri=accepted["tos_uri"],
        registration_metadata=accepted["extra"],
        registration_access_token_hash=oauth2.hash_token(registration_access_token),
        registered_with_token_id=str(token_row["id"]) if token_row else None,
        available_to_all=available_to_all,
    )
    if token_row is not None:
        database.oauth2.touch_initial_access_token(tenant_id, str(token_row["id"]))

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oauth2_client",
        artifact_id=str(client["id"]),
        event_type="oauth2_client_registered",
        metadata={
            "name": client["name"],
            "client_id": client["client_id"],
            "redirect_uris": accepted["redirect_uris"],
            "available_to_all": available_to_all,
            "initial_access_token_id": str(token_row["id"]) if token_row else None,
            "initial_access_token_name": token_row["name"] if token_row else None,
        },
    )

    body = client_configuration(client, base_url)
    body["client_secret"] = client["client_secret"]
    body["client_secret_expires_at"] = 0
    body["registration_access_token"] = registration_access_token
    return body


# =============================================================================
# Protocol: client configuration (RFC 7592)
# =============================================================================


def authenticate_registration(
    tenant_id: str, client_id: str, registration_access_token: str | None
) -> dict:
    """Return the client a registration access token belongs to.

    Unknown, deactivated, statically created, and mismatched all fail the same
    way (RFC 7592 section 2: 401, so the endpoint never confirms a client_id).

    Raises:
        UnauthorizedError: the token does not open this client's configuration
    """
    if not registration_access_token:
        raise UnauthorizedError(message="A registration access token is required")
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    stored_hash = client.get("registration_access_token_hash") if client else None
    if (
        client is None
        or not client.get("dynamically_registered")
        or not client.get("is_active", True)
        or not stored_hash
        or not oauth2.verify_token_hash(registration_access_token, stored_hash)
    ):
        raise UnauthorizedError(message="The registration access token is not valid")
    return client


def read_client_configuration(client: dict, base_url: str) -> dict:
    """RFC 7592 section 2.1. A read writes nothing: no event (the client, not a
    user, is the caller, so there is no activity to track either)."""
    return client_configuration(client, base_url)


def update_client_configuration(
    tenant_id: str, client: dict, metadata: dict, base_url: str
) -> dict:
    """Replace a registered client's metadata (RFC 7592 section 2.2).

    Omitted metadata returns to its default. ``client_id`` must be present and
    match; a ``client_secret``, if sent, must be the current one. The
    server-managed fields (``registration_access_token``,
    ``registration_client_uri``, ``client_secret_expires_at``,
    ``client_id_issued_at``) are ignored. Credentials and access settings are
    unchanged.

    Logs: oauth2_client_registration_updated (system actor).

    Raises:
        ValidationError: invalid metadata or a client_id/client_secret mismatch
    """
    if not isinstance(metadata, dict):
        raise _metadata_error("The request body must be a JSON object")
    if metadata.get("client_id") != client["client_id"]:
        raise _metadata_error("client_id must be present and match the client")
    secret = metadata.get("client_secret")
    if secret is not None:
        full = database.oauth2.get_client_by_client_id(tenant_id, client["client_id"])
        if (
            not isinstance(secret, str)
            or full is None
            or not oauth2.verify_token_hash(secret, full["client_secret_hash"])
        ):
            raise _metadata_error("client_secret does not match")

    accepted = validate_client_metadata(metadata)
    updated = database.oauth2.replace_registered_client(
        tenant_id,
        client["client_id"],
        name=accepted["client_name"],
        redirect_uris=accepted["redirect_uris"],
        post_logout_redirect_uris=accepted["post_logout_redirect_uris"],
        frontchannel_logout_uri=accepted["frontchannel_logout_uri"],
        frontchannel_logout_session_required=accepted["frontchannel_logout_session_required"],
        backchannel_logout_uri=accepted["backchannel_logout_uri"],
        backchannel_logout_session_required=accepted["backchannel_logout_session_required"],
        logo_uri=accepted["logo_uri"],
        client_uri=accepted["client_uri"],
        policy_uri=accepted["policy_uri"],
        tos_uri=accepted["tos_uri"],
        registration_metadata=accepted["extra"],
    )
    if updated is None:
        raise UnauthorizedError(message="The registration access token is not valid")

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oauth2_client",
        artifact_id=str(updated["id"]),
        event_type="oauth2_client_registration_updated",
        metadata={
            "name": updated["name"],
            "client_id": updated["client_id"],
            "redirect_uris": accepted["redirect_uris"],
        },
    )
    return client_configuration(updated, base_url)


def delete_client_configuration(tenant_id: str, client: dict) -> None:
    """Delete a registered client (RFC 7592 section 2.3). Its tokens, codes and
    consent grants go with it (cascade).

    Logs: oauth2_client_registration_deleted (system actor).
    """
    rows = database.oauth2.delete_client(tenant_id, client["client_id"])
    if rows:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_registration_deleted",
            metadata={"name": client["name"], "client_id": client["client_id"]},
        )
