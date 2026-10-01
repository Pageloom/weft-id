"""OAuth2 service layer.

This module provides business logic for OAuth2 operations:
- Client lookup and validation
- Authorization code creation
- Token creation and validation

All functions:
- Are utility functions without authorization (OAuth2 has its own auth)
- Return data from database layer
- Have no knowledge of HTTP concepts
"""

from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import database
from services.event_log import log_event
from services.exceptions import ValidationError

# Upper bound on registered post-logout redirect URIs (matches the CHECK
# constraint on oauth2_clients.post_logout_redirect_uris).
MAX_POST_LOGOUT_REDIRECT_URIS = 50


def validate_post_logout_redirect_uris(uris: list[str]) -> list[str]:
    """Normalise and validate a client's post-logout redirect URIs.

    Each URI must be absolute ``http``/``https`` with a host and no fragment
    (OpenID Connect RP-Initiated Logout 1.0 section 3; the end_session
    endpoint compares them by exact string match). Blank entries and
    duplicates are dropped, order is kept.

    Raises:
        ValidationError: code ``invalid_post_logout_redirect_uri`` for a
            malformed URI or too many URIs.
    """
    cleaned: list[str] = []
    for raw in uris:
        uri = raw.strip()
        if not uri or uri in cleaned:
            continue
        try:
            parts = urlsplit(uri)
        except ValueError:
            parts = None
        if (
            parts is None
            or parts.scheme not in ("http", "https")
            or not parts.netloc
            or parts.fragment
            or "#" in uri
        ):
            raise ValidationError(
                f"Invalid post-logout redirect URI: {uri[:200]}",
                code="invalid_post_logout_redirect_uri",
            )
        cleaned.append(uri)
    if len(cleaned) > MAX_POST_LOGOUT_REDIRECT_URIS:
        raise ValidationError(
            f"At most {MAX_POST_LOGOUT_REDIRECT_URIS} post-logout redirect URIs are allowed",
            code="invalid_post_logout_redirect_uri",
        )
    return cleaned


def _origin(parts) -> tuple[str, str, int | None] | None:
    """``(scheme, host, port)`` of a parsed URL with default ports filled in."""
    try:
        port = parts.port
    except ValueError:
        return None
    if parts.hostname is None:
        return None
    scheme = parts.scheme.lower()
    return scheme, parts.hostname.lower(), port or {"http": 80, "https": 443}.get(scheme)


def validate_frontchannel_logout_uri(uri: str | None, redirect_uris: list[str]) -> str | None:
    """Normalise and validate a client's front-channel logout URI.

    Blank means "none" and returns None. Otherwise the URI must be absolute
    ``http``/``https`` with a host and no fragment, and its scheme, host and
    port must be those of one of the client's registered redirect URIs
    (OpenID Connect Front-Channel Logout 1.0, section 2). A query is allowed;
    the logout parameters are appended to it.

    Raises:
        ValidationError: code ``invalid_frontchannel_logout_uri``.
    """
    cleaned = (uri or "").strip()
    if not cleaned:
        return None
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        parts = None
    origin = _origin(parts) if parts is not None else None
    if (
        parts is None
        or origin is None
        or parts.scheme.lower() not in ("http", "https")
        or parts.fragment
        or "#" in cleaned
    ):
        raise ValidationError(
            f"Invalid front-channel logout URI: {cleaned[:200]}",
            code="invalid_frontchannel_logout_uri",
        )
    redirect_origins = set()
    for redirect_uri in redirect_uris:
        try:
            redirect_origin = _origin(urlsplit(redirect_uri))
        except ValueError:
            continue
        if redirect_origin is not None:
            redirect_origins.add(redirect_origin)
    if origin not in redirect_origins:
        raise ValidationError(
            "The front-channel logout URI must use the scheme, host and port of one of "
            "the client's redirect URIs",
            code="invalid_frontchannel_logout_uri",
        )
    return cleaned


def validate_backchannel_logout_uri(uri: str | None) -> str | None:
    """Normalise and validate a client's back-channel logout URI.

    Blank means "none" and returns None. Otherwise the URI must be absolute
    ``http``/``https`` with a host (and a valid port, if any) and no fragment
    (OpenID Connect Back-Channel Logout 1.0, section 2.2). Unlike the
    front-channel URI it need not share a redirect URI's origin: WeftID calls
    it server to server, through the SSRF-guarded HTTP client.

    Raises:
        ValidationError: code ``invalid_backchannel_logout_uri``.
    """
    cleaned = (uri or "").strip()
    if not cleaned:
        return None
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        parts = None
    if (
        parts is None
        or _origin(parts) is None
        or parts.scheme.lower() not in ("http", "https")
        or parts.fragment
        or "#" in cleaned
    ):
        raise ValidationError(
            f"Invalid back-channel logout URI: {cleaned[:200]}",
            code="invalid_backchannel_logout_uri",
        )
    return cleaned


def validate_initiate_login_uri(uri: str | None) -> str | None:
    """Normalise and validate a client's third-party login initiation URI.

    Blank means "none" and returns None. Otherwise the URI must be absolute
    ``https`` with a host (and a valid port, if any) and no fragment (OpenID
    Connect Registration 1.0 section 2, ``initiate_login_uri``). A query is
    allowed; the login parameters are appended to it.

    Raises:
        ValidationError: code ``invalid_initiate_login_uri``.
    """
    cleaned = (uri or "").strip()
    if not cleaned:
        return None
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        parts = None
    if (
        parts is None
        or _origin(parts) is None
        or parts.scheme.lower() != "https"
        or parts.fragment
        or "#" in cleaned
    ):
        raise ValidationError(
            f"Invalid login initiation URI: {cleaned[:200]}",
            code="invalid_initiate_login_uri",
        )
    return cleaned


def initiate_login_url(initiate_login_uri: str, issuer: str) -> str:
    """The URL that asks a client to start a login at WeftID.

    OpenID Connect Core 1.0 section 4: ``iss`` is the only required parameter.
    ``target_link_uri`` is left out (the client lands where it normally would)
    and so is ``login_hint`` (the user already has a WeftID session, and the
    hint would put their email address in the client's request logs).
    """
    parts = urlsplit(initiate_login_uri)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "iss"]
    query = urlencode([*kept, ("iss", issuer)])
    return urlunsplit(parts._replace(query=query))


# =============================================================================
# Client Operations
# =============================================================================


def get_client_by_client_id(tenant_id: str, client_id: str) -> dict | None:
    """
    Get an OAuth2 client by its client_id.

    Args:
        tenant_id: Tenant ID
        client_id: OAuth2 client identifier

    Returns:
        Client dict or None if not found
    """
    return database.oauth2.get_client_by_client_id(tenant_id, client_id)


# =============================================================================
# Authorization Code Operations
# =============================================================================


def create_authorization_code(
    tenant_id: str,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    scope: str | None = None,
    nonce: str | None = None,
    auth_time: datetime | None = None,
    sid: str | None = None,
) -> str:
    """
    Create an authorization code for OAuth2 authorization code flow.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID (not the client_id string)
        user_id: User UUID authorizing the request
        redirect_uri: Registered redirect URI
        code_challenge: Optional PKCE code challenge
        code_challenge_method: Optional PKCE method (S256 or plain)
        scope: Optional OIDC/OAuth2 space-delimited scope string
        nonce: Optional OIDC nonce to bind to the resulting ID token
        auth_time: Optional user authentication time to record in the ID token
        sid: Optional WeftID session identifier to record in the ID token

    Returns:
        Authorization code string
    """
    # Redeemed codes are kept (marked consumed) until they expire so a reuse
    # can be detected. Sweep the tenant's expired codes here, on the path that
    # adds rows, so the table stays bounded to codes from the last few minutes.
    database.oauth2.cleanup_expired_codes(tenant_id)
    return database.oauth2.create_authorization_code(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        nonce=nonce,
        auth_time=auth_time,
        sid=sid,
    )


def validate_and_consume_code(
    tenant_id: str,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str | None = None,
) -> dict | None:
    """
    Validate and consume an authorization code.

    The code is marked consumed upon successful validation. A code redeemed a
    second time is rejected like an invalid one, and every token already
    issued from it is revoked (RFC 6749 section 4.1.2: the code has leaked).

    Logs: ``oauth2_authorization_code_reused`` when a reuse is detected.

    Args:
        tenant_id: Tenant ID
        code: Authorization code to validate
        client_id: Internal client UUID
        redirect_uri: Redirect URI (must match original)
        code_verifier: Optional PKCE code verifier

    Returns:
        Code data dict (``id`` is the grant id for the tokens issued from it,
        plus user_id, scope, nonce, auth_time, sid), or None if invalid or reused
    """
    code_data = database.oauth2.validate_and_consume_code(
        tenant_id=tenant_id,
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )
    if code_data is None:
        return None

    if code_data.pop("reused"):
        revoked = database.oauth2.revoke_grant_tokens(tenant_id, code_data["id"])
        log_event(
            tenant_id=tenant_id,
            actor_user_id=str(code_data["user_id"]),
            artifact_type="oauth2_client",
            artifact_id=str(client_id),
            event_type="oauth2_authorization_code_reused",
            metadata={"grant_id": code_data["id"], "tokens_revoked": revoked},
        )
        return None

    return code_data


# =============================================================================
# Token Operations
# =============================================================================


def create_refresh_token(
    tenant_id: str,
    client_id: str,
    user_id: str,
    scope: str | None = None,
    grant_id: str | None = None,
    sid: str | None = None,
) -> tuple[str, str]:
    """
    Create a refresh token.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID
        user_id: User UUID
        scope: Optional granted space-delimited scope string (persisted so the
            refresh_token grant can carry it onto refreshed access tokens)
        grant_id: Optional id of the authorization code that started the grant
        sid: Optional WeftID session the token is issued in. Set only when an
            ID token carrying the same ``sid`` is issued with it; ending that
            session then revokes the token (Back-Channel Logout 1.0, 2.7)

    Returns:
        Tuple of (refresh_token_string, refresh_token_id)
    """
    return database.oauth2.create_refresh_token(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        grant_id=grant_id,
        sid=sid,
    )


def create_access_token(
    tenant_id: str,
    client_id: str,
    user_id: str,
    parent_token_id: str | None = None,
    is_client_credentials: bool = False,
    scope: str | None = None,
    grant_id: str | None = None,
) -> str:
    """
    Create an access token.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID
        user_id: User UUID
        parent_token_id: Optional refresh token ID (for linked tokens)
        is_client_credentials: True if this is a client_credentials grant
        scope: Optional granted space-delimited scope string (persisted so
            downstream userinfo can gate released claims)
        grant_id: Optional id of the authorization code that started the grant

    Returns:
        Access token string
    """
    return database.oauth2.create_access_token(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_id,
        user_id=user_id,
        parent_token_id=parent_token_id,
        is_client_credentials=is_client_credentials,
        scope=scope,
        grant_id=grant_id,
    )


def validate_refresh_token(
    tenant_id: str,
    token: str,
    client_id: str,
) -> dict | None:
    """
    Validate a refresh token.

    Args:
        tenant_id: Tenant ID
        token: Refresh token string
        client_id: Internal client UUID

    Returns:
        Token data dict with id, user_id, tenant_id, the persisted granted
        scope, grant_id and expires_at, or None if invalid
    """
    return database.oauth2.validate_refresh_token(
        tenant_id=tenant_id,
        token=token,
        client_id=client_id,
    )


def rotate_refresh_token(
    tenant_id: str,
    client_id: str,
    token_data: dict,
) -> tuple[str, str] | None:
    """
    Replace a validated refresh token with a new one (refresh token rotation).

    The new token keeps the old one's user, scope, grant, session, and absolute
    expiry, so rotation never extends how long a grant lives; the old token stops
    working immediately. Access tokens issued under the old token stay valid
    until they expire.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID
        token_data: The dict returned by ``validate_refresh_token``

    Returns:
        Tuple of (refresh_token_string, refresh_token_id), or None when a
        concurrent request already redeemed the old token
    """
    return database.oauth2.rotate_refresh_token(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        old_token_id=str(token_data["id"]),
        client_id=client_id,
        user_id=str(token_data["user_id"]),
        scope=token_data.get("scope"),
        grant_id=str(token_data["grant_id"]) if token_data.get("grant_id") else None,
        expires_at=token_data["expires_at"],
        sid=token_data.get("sid"),
    )


# =============================================================================
# Client Management Operations
# =============================================================================


def get_all_clients(tenant_id: str, client_type: str | None = None) -> list[dict]:
    """
    Get all OAuth2 clients for a tenant.

    Args:
        tenant_id: Tenant ID
        client_type: Optional filter by client type ('normal' or 'b2b')

    Returns:
        List of client dicts
    """
    return database.oauth2.get_all_clients(tenant_id, client_type=client_type)


def create_normal_client(
    tenant_id: str,
    name: str,
    redirect_uris: list[str],
    created_by: str,
    description: str | None = None,
    post_logout_redirect_uris: list[str] | None = None,
    frontchannel_logout_uri: str | None = None,
    frontchannel_logout_session_required: bool = True,
    backchannel_logout_uri: str | None = None,
    backchannel_logout_session_required: bool = True,
    initiate_login_uri: str | None = None,
    device_grant_enabled: bool = False,
) -> dict:
    """
    Create a normal OAuth2 client (authorization code flow).

    Args:
        tenant_id: Tenant ID
        name: Client name
        redirect_uris: List of allowed redirect URIs
        created_by: User ID who created the client
        description: Optional client description
        post_logout_redirect_uris: Optional URIs the end_session endpoint may
            redirect to after logout
        frontchannel_logout_uri: Optional RP URL loaded in an iframe when the
            user's session ends (same origin as a redirect URI)
        frontchannel_logout_session_required: Whether that URL receives
            ``iss`` and ``sid``
        backchannel_logout_uri: Optional RP URL the logout token is POSTed to
            when the user's session ends
        backchannel_logout_session_required: Whether the logout token carries
            ``sid``
        initiate_login_uri: Optional https URL of the app that starts a login
            at WeftID (third-party-initiated login, My Apps launch)
        device_grant_enabled: Whether the client may use the device
            authorization grant (RFC 8628)

    Returns:
        Client dict including plaintext client_secret

    Raises:
        ValidationError: a post-logout redirect URI, a front- or back-channel
            logout URI, or the login initiation URI is malformed
    """
    post_logout_uris = validate_post_logout_redirect_uris(post_logout_redirect_uris or [])
    frontchannel_uri = validate_frontchannel_logout_uri(frontchannel_logout_uri, redirect_uris)
    backchannel_uri = validate_backchannel_logout_uri(backchannel_logout_uri)
    initiate_uri = validate_initiate_login_uri(initiate_login_uri)
    result = database.oauth2.create_normal_client(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        redirect_uris=redirect_uris,
        created_by=created_by,
        description=description,
        post_logout_redirect_uris=post_logout_uris,
        frontchannel_logout_uri=frontchannel_uri,
        frontchannel_logout_session_required=frontchannel_logout_session_required,
        backchannel_logout_uri=backchannel_uri,
        backchannel_logout_session_required=backchannel_logout_session_required,
        initiate_login_uri=initiate_uri,
        device_grant_enabled=device_grant_enabled,
    )

    if result is None:
        raise ValidationError("Failed to create OAuth2 client", code="client_creation_failed")

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=created_by,
        artifact_type="oauth2_client",
        artifact_id=str(result["id"]),
        event_type="oauth2_client_created",
        metadata={
            "name": name,
            "type": "normal",
            "client_id": result["client_id"],
            "device_grant_enabled": device_grant_enabled,
        },
    )

    return result


def create_b2b_client(
    tenant_id: str,
    name: str,
    role: str,
    created_by: str,
    description: str | None = None,
) -> dict:
    """
    Create a B2B OAuth2 client (client credentials flow).

    Creates a service user with the specified role and links it.

    Args:
        tenant_id: Tenant ID
        name: Client name (used as service user first_name)
        role: Role for service user (member, admin, super_admin)
        created_by: User ID who created the client
        description: Optional client description

    Returns:
        Client dict including plaintext client_secret
    """
    result = database.oauth2.create_b2b_client(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        role=role,
        created_by=created_by,
        description=description,
    )

    if result is None:
        raise ValidationError(
            "Failed to create B2B OAuth2 client", code="b2b_client_creation_failed"
        )

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=created_by,
        artifact_type="oauth2_client",
        artifact_id=str(result["id"]),
        event_type="oauth2_client_created",
        metadata={
            "name": name,
            "type": "b2b",
            "role": role,
            "client_id": result["client_id"],
            "service_user_id": str(result.get("service_user_id")),
        },
    )

    return result


def delete_client(tenant_id: str, client_id: str, actor_user_id: str) -> int:
    """
    Delete an OAuth2 client.

    Cascades to delete tokens and authorization codes.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string (e.g., "weft-id_client_abc123")
        actor_user_id: User ID performing the deletion

    Returns:
        Number of rows deleted (0 if not found)
    """
    # Get client info before deletion for logging
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not client:
        return 0

    rows = database.oauth2.delete_client(tenant_id, client_id)

    if rows > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_deleted",
            metadata={"name": client["name"], "client_id": client_id},
        )

    return rows


def regenerate_client_secret(tenant_id: str, client_id: str, actor_user_id: str) -> str:
    """
    Regenerate the client secret.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string
        actor_user_id: User ID performing the regeneration

    Returns:
        New plaintext client secret
    """
    # Get client info for logging
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)

    new_secret = database.oauth2.regenerate_client_secret(tenant_id, client_id)

    if client:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_secret_regenerated",
            metadata={"name": client["name"], "client_id": client_id},
        )

    return new_secret


def update_client(
    tenant_id: str,
    client_id: str,
    actor_user_id: str,
    name: str | None = None,
    description: str | None = None,
    redirect_uris: list[str] | None = None,
    post_logout_redirect_uris: list[str] | None = None,
    frontchannel_logout_uri: str | None = None,
    frontchannel_logout_session_required: bool | None = None,
    backchannel_logout_uri: str | None = None,
    backchannel_logout_session_required: bool | None = None,
    initiate_login_uri: str | None = None,
    device_grant_enabled: bool | None = None,
) -> dict | None:
    """
    Update an OAuth2 client's name, description, redirect URIs, logout settings,
    login initiation URI, and device authorization grant switch.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string (e.g., "weft-id_client_abc123")
        actor_user_id: User ID performing the update
        name: New client name (optional)
        description: New description (optional)
        redirect_uris: New redirect URIs for normal clients (optional)
        post_logout_redirect_uris: New post-logout redirect URIs for normal
            clients (optional; an empty list clears them)
        frontchannel_logout_uri: New front-channel logout URI for normal
            clients (optional; an empty string clears it)
        frontchannel_logout_session_required: Whether the front-channel
            logout URI receives ``iss`` and ``sid`` (optional)
        backchannel_logout_uri: New back-channel logout URI for normal
            clients (optional; an empty string clears it)
        backchannel_logout_session_required: Whether the logout token carries
            ``sid`` (optional)
        initiate_login_uri: New login initiation URI for normal clients
            (optional; https only; an empty string clears it)
        device_grant_enabled: Whether the device authorization grant is
            allowed (optional; normal clients only)

    Returns:
        Updated client dict, or None if not found

    Raises:
        ValidationError: URIs or logout settings given for a B2B client, a
            malformed post-logout redirect URI, a front-channel logout URI
            that is malformed or not on a redirect URI's origin (checked
            against the redirect URIs the client will have after the update),
            a malformed back-channel logout URI, a login initiation URI
            that is malformed or not https, or the device grant switched on
            for a B2B client
    """
    # Get current client for comparison
    old_client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not old_client:
        return None

    # Validate: redirect_uris only allowed for normal clients
    if redirect_uris is not None and old_client["client_type"] != "normal":
        raise ValidationError(
            "Redirect URIs can only be set for normal clients",
            code="redirect_uris_not_allowed",
        )
    if post_logout_redirect_uris is not None:
        if old_client["client_type"] != "normal":
            raise ValidationError(
                "Post-logout redirect URIs can only be set for normal clients",
                code="redirect_uris_not_allowed",
            )
        post_logout_redirect_uris = validate_post_logout_redirect_uris(post_logout_redirect_uris)
    if frontchannel_logout_uri is not None or frontchannel_logout_session_required is not None:
        if old_client["client_type"] != "normal":
            raise ValidationError(
                "Front-channel logout can only be set for normal clients",
                code="redirect_uris_not_allowed",
            )
    if backchannel_logout_uri is not None or backchannel_logout_session_required is not None:
        if old_client["client_type"] != "normal":
            raise ValidationError(
                "Back-channel logout can only be set for normal clients",
                code="redirect_uris_not_allowed",
            )
        if backchannel_logout_uri is not None:
            backchannel_logout_uri = validate_backchannel_logout_uri(backchannel_logout_uri) or ""
    if initiate_login_uri is not None:
        if old_client["client_type"] != "normal":
            raise ValidationError(
                "A login initiation URI can only be set for normal clients",
                code="redirect_uris_not_allowed",
            )
        initiate_login_uri = validate_initiate_login_uri(initiate_login_uri) or ""
    if device_grant_enabled and old_client["client_type"] != "normal":
        raise ValidationError(
            "The device authorization grant can only be enabled for normal clients",
            code="device_grant_not_allowed",
        )
    # Re-check the front-channel URI whenever it or the redirect URIs change:
    # it must stay on the origin of a registered redirect URI.
    if frontchannel_logout_uri is not None or redirect_uris is not None:
        effective_uri = (
            frontchannel_logout_uri
            if frontchannel_logout_uri is not None
            else old_client.get("frontchannel_logout_uri")
        )
        effective_redirects = (
            redirect_uris if redirect_uris is not None else old_client.get("redirect_uris") or []
        )
        validated = validate_frontchannel_logout_uri(effective_uri, effective_redirects)
        if frontchannel_logout_uri is not None:
            frontchannel_logout_uri = validated or ""

    result = database.oauth2.update_client(
        tenant_id=tenant_id,
        client_id=client_id,
        name=name,
        description=description,
        redirect_uris=redirect_uris,
        post_logout_redirect_uris=post_logout_redirect_uris,
        frontchannel_logout_uri=frontchannel_logout_uri,
        frontchannel_logout_session_required=frontchannel_logout_session_required,
        backchannel_logout_uri=backchannel_logout_uri,
        backchannel_logout_session_required=backchannel_logout_session_required,
        initiate_login_uri=initiate_login_uri,
        device_grant_enabled=device_grant_enabled,
    )

    if result:
        # Build list of changed fields for audit log
        changed_fields = []
        if name is not None and name != old_client.get("name"):
            changed_fields.append("name")
        if description is not None and description != old_client.get("description"):
            changed_fields.append("description")
        if redirect_uris is not None and redirect_uris != old_client.get("redirect_uris"):
            changed_fields.append("redirect_uris")
        if post_logout_redirect_uris is not None and post_logout_redirect_uris != (
            old_client.get("post_logout_redirect_uris") or []
        ):
            changed_fields.append("post_logout_redirect_uris")
        if frontchannel_logout_uri is not None and (frontchannel_logout_uri or None) != (
            old_client.get("frontchannel_logout_uri")
        ):
            changed_fields.append("frontchannel_logout_uri")
        if frontchannel_logout_session_required is not None and (
            frontchannel_logout_session_required
            != bool(old_client.get("frontchannel_logout_session_required"))
        ):
            changed_fields.append("frontchannel_logout_session_required")
        if backchannel_logout_uri is not None and (backchannel_logout_uri or None) != (
            old_client.get("backchannel_logout_uri")
        ):
            changed_fields.append("backchannel_logout_uri")
        if backchannel_logout_session_required is not None and (
            backchannel_logout_session_required
            != bool(old_client.get("backchannel_logout_session_required"))
        ):
            changed_fields.append("backchannel_logout_session_required")
        if initiate_login_uri is not None and (initiate_login_uri or None) != (
            old_client.get("initiate_login_uri")
        ):
            changed_fields.append("initiate_login_uri")
        if device_grant_enabled is not None and device_grant_enabled != bool(
            old_client.get("device_grant_enabled")
        ):
            changed_fields.append("device_grant_enabled")

        if changed_fields:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                artifact_type="oauth2_client",
                artifact_id=str(result["id"]),
                event_type="oauth2_client_updated",
                metadata={
                    "name": result["name"],
                    "client_id": client_id,
                    "changed_fields": changed_fields,
                },
            )

    return result


def update_b2b_client_role(
    tenant_id: str,
    client_id: str,
    role: str,
    actor_user_id: str,
) -> dict | None:
    """
    Update the service user role for a B2B OAuth2 client.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string
        role: New role ('member', 'admin', 'super_admin')
        actor_user_id: User ID performing the update

    Returns:
        Updated client dict with service_role, or None if not found
    """
    # Get current client for comparison
    old_client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not old_client:
        return None

    if old_client["client_type"] != "b2b":
        raise ValidationError(
            "Role can only be changed for B2B clients",
            code="role_change_not_allowed",
        )

    result = database.oauth2.update_b2b_client_role(tenant_id, client_id, role)

    if result:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(result["id"]),
            event_type="oauth2_client_role_changed",
            metadata={
                "name": result["name"],
                "client_id": client_id,
                "new_role": role,
                "service_user_id": str(result.get("service_user_id")),
            },
        )

    return result


def deactivate_client(tenant_id: str, client_id: str, actor_user_id: str) -> dict | None:
    """
    Deactivate an OAuth2 client (soft delete).

    Also revokes all tokens for this client and deletes every remembered
    consent grant, so users re-consent if the client is reactivated.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string
        actor_user_id: User ID performing the deactivation

    Returns:
        Updated client dict, or None if not found
    """
    # Get current client
    old_client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not old_client:
        return None

    result = database.oauth2.deactivate_client(tenant_id, client_id)

    if result:
        # Revoke all tokens for this client and forget every consent grant
        database.oauth2.revoke_all_client_tokens(tenant_id, str(old_client["id"]))
        consents_revoked = database.oauth2.delete_consent_grants_for_client(
            tenant_id, str(old_client["id"])
        )

        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(result["id"]),
            event_type="oauth2_client_deactivated",
            metadata={
                "name": result["name"],
                "client_id": client_id,
                "client_type": result["client_type"],
                "consents_revoked": consents_revoked,
            },
        )

    return result


def reactivate_client(tenant_id: str, client_id: str, actor_user_id: str) -> dict | None:
    """
    Reactivate a deactivated OAuth2 client.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string
        actor_user_id: User ID performing the reactivation

    Returns:
        Updated client dict, or None if not found
    """
    result = database.oauth2.reactivate_client(tenant_id, client_id)

    if result:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(result["id"]),
            event_type="oauth2_client_reactivated",
            metadata={
                "name": result["name"],
                "client_id": client_id,
                "client_type": result["client_type"],
            },
        )

    return result


def get_client_by_id(tenant_id: str, id: str) -> dict | None:
    """
    Get an OAuth2 client by its internal UUID.

    Args:
        tenant_id: Tenant ID
        id: Internal client UUID

    Returns:
        Client dict or None if not found
    """
    return database.oauth2.get_client_by_id(tenant_id, id)
