"""Dynamic client registration database operations (RFC 7591 / RFC 7592).

- ``oauth2_registration_settings``: the tenant's registration policy and the
  default access for newly registered clients. A missing row means the
  defaults (``off`` / ``none``).
- ``oauth2_initial_access_tokens``: admin-issued bearer tokens that authorize
  a registration. Only the SHA-256 hex digest is stored; the hash never leaves
  this module.
- Dynamically registered rows in ``oauth2_clients``: created and replaced here
  (RFC 7592 update is a full replacement), deleted with the ordinary
  ``delete_client``.
"""

import oauth2
from database._core import TenantArg, execute, fetchall, fetchone
from psycopg.types.json import Json

# Columns a registered client is returned with (the shape of
# ``get_client_by_client_id`` minus the two hashes).
_CLIENT_COLUMNS = """
    id, tenant_id, client_id, client_type, name, description,
    redirect_uris, post_logout_redirect_uris, frontchannel_logout_uri,
    backchannel_logout_uri, backchannel_logout_session_required,
    frontchannel_logout_session_required, service_user_id, is_active,
    oidc_enabled, available_to_all, can_introspect_tenant_tokens, dynamically_registered,
    logo_uri, client_uri, policy_uri, tos_uri, initiate_login_uri, device_grant_enabled,
    is_public, registration_metadata, registered_with_token_id, created_at
"""

_TOKEN_COLUMNS = """
    t.id, t.tenant_id, t.name, t.created_by, t.created_at, t.expires_at,
    t.revoked_at, t.last_used_at
"""


# =============================================================================
# Registration settings
# =============================================================================


def get_registration_settings(tenant_id: TenantArg) -> dict | None:
    """Return the tenant's ``policy`` and ``default_access``, or None when unset."""
    return fetchone(
        tenant_id,
        """
        select policy, default_access, updated_by, updated_at
        from oauth2_registration_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def upsert_registration_settings(
    tenant_id: TenantArg,
    tenant_id_value: str,
    policy: str,
    default_access: str,
    updated_by: str,
) -> dict:
    """Create or replace the tenant's registration settings."""
    result = fetchone(
        tenant_id,
        """
        insert into oauth2_registration_settings (
            tenant_id, policy, default_access, updated_by
        ) values (
            :tenant_id, :policy, :default_access, :updated_by
        )
        on conflict (tenant_id) do update set
            policy = excluded.policy,
            default_access = excluded.default_access,
            updated_by = excluded.updated_by,
            updated_at = now()
        returning policy, default_access, updated_by, updated_at
        """,
        {
            "tenant_id": tenant_id_value,
            "policy": policy,
            "default_access": default_access,
            "updated_by": updated_by,
        },
    )
    assert result is not None  # INSERT ... RETURNING always returns a row
    return result


# =============================================================================
# Initial access tokens
# =============================================================================


def create_initial_access_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    token_hash: str,
    created_by: str,
    expires_at=None,
) -> dict:
    """Insert an initial access token. ``token_hash`` is the SHA-256 hex digest."""
    result = fetchone(
        tenant_id,
        """
        insert into oauth2_initial_access_tokens (
            tenant_id, name, token_hash, created_by, expires_at
        ) values (
            :tenant_id, :name, :token_hash, :created_by, :expires_at
        )
        returning id, tenant_id, name, created_by, created_at, expires_at,
                  revoked_at, last_used_at
        """,
        {
            "tenant_id": tenant_id_value,
            "name": name,
            "token_hash": token_hash,
            "created_by": created_by,
            "expires_at": expires_at,
        },
    )
    assert result is not None  # INSERT ... RETURNING always returns a row
    return result


def list_initial_access_tokens(tenant_id: TenantArg) -> list[dict]:
    """All initial access tokens, newest first, with the creator's name and the
    number of clients each one registered (revoked and expired included)."""
    return fetchall(
        tenant_id,
        f"""
        select {_TOKEN_COLUMNS},
               u.first_name as created_by_first_name,
               u.last_name as created_by_last_name,
               (select count(*) from oauth2_clients c
                where c.registered_with_token_id = t.id) as registered_client_count
        from oauth2_initial_access_tokens t
        left join users u on u.id = t.created_by
        order by t.created_at desc
        """,
        {},
    )


def get_initial_access_token(tenant_id: TenantArg, token_id: str) -> dict | None:
    """One initial access token by id (no hash)."""
    return fetchone(
        tenant_id,
        f"""
        select {_TOKEN_COLUMNS}
        from oauth2_initial_access_tokens t
        where t.id = :id
        """,
        {"id": token_id},
    )


def get_initial_access_token_by_hash(tenant_id: TenantArg, token_hash: str) -> dict | None:
    """Look an initial access token up by its SHA-256 hex digest.

    Returned regardless of revocation or expiry; the caller decides.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_TOKEN_COLUMNS}
        from oauth2_initial_access_tokens t
        where t.token_hash = :token_hash
        """,
        {"token_hash": token_hash},
    )


def revoke_initial_access_token(tenant_id: TenantArg, token_id: str) -> dict | None:
    """Revoke a token. Returns the row, or None when missing or already revoked."""
    return fetchone(
        tenant_id,
        """
        update oauth2_initial_access_tokens
        set revoked_at = now()
        where id = :id and revoked_at is null
        returning id, tenant_id, name, created_by, created_at, expires_at,
                  revoked_at, last_used_at
        """,
        {"id": token_id},
    )


def touch_initial_access_token(tenant_id: TenantArg, token_id: str) -> int:
    """Record that the token authorized a registration just now."""
    return execute(
        tenant_id,
        "update oauth2_initial_access_tokens set last_used_at = now() where id = :id",
        {"id": token_id},
    )


# =============================================================================
# Registered clients
# =============================================================================


def create_registered_client(
    tenant_id: TenantArg,
    tenant_id_value: str,
    *,
    name: str,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str],
    frontchannel_logout_uri: str | None,
    frontchannel_logout_session_required: bool,
    backchannel_logout_uri: str | None,
    backchannel_logout_session_required: bool,
    logo_uri: str | None,
    client_uri: str | None,
    policy_uri: str | None,
    tos_uri: str | None,
    initiate_login_uri: str | None,
    registration_metadata: dict,
    registration_access_token_hash: str,
    registered_with_token_id: str | None,
    available_to_all: bool,
    device_grant_enabled: bool = False,
    is_public: bool = False,
) -> dict:
    """Insert a dynamically registered client.

    Always a ``normal`` client with OIDC enabled and no creating user. Returns
    the row plus the plaintext ``client_secret``, which exists only in this
    return value. A public client gets no secret (it stores the hash of one
    nobody ever sees).
    """
    client_secret = oauth2.generate_client_secret()
    client = fetchone(
        tenant_id,
        f"""
        insert into oauth2_clients (
            tenant_id, client_id, client_secret_hash, client_type, name,
            redirect_uris, post_logout_redirect_uris,
            frontchannel_logout_uri, frontchannel_logout_session_required,
            backchannel_logout_uri, backchannel_logout_session_required,
            oidc_enabled, available_to_all, dynamically_registered,
            logo_uri, client_uri, policy_uri, tos_uri, initiate_login_uri,
            device_grant_enabled, is_public,
            registration_metadata, registration_access_token_hash, registered_with_token_id,
            created_by
        ) values (
            :tenant_id, :client_id, :client_secret_hash, 'normal', :name,
            :redirect_uris, :post_logout_redirect_uris,
            :frontchannel_logout_uri, :frontchannel_logout_session_required,
            :backchannel_logout_uri, :backchannel_logout_session_required,
            true, :available_to_all, true,
            :logo_uri, :client_uri, :policy_uri, :tos_uri, :initiate_login_uri,
            :device_grant_enabled, :is_public,
            :registration_metadata, :registration_access_token_hash, :registered_with_token_id,
            null
        )
        returning {_CLIENT_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": oauth2.generate_client_id(),
            "client_secret_hash": oauth2.hash_token(client_secret),
            "name": name,
            "redirect_uris": redirect_uris,
            "post_logout_redirect_uris": post_logout_redirect_uris,
            "frontchannel_logout_uri": frontchannel_logout_uri,
            "frontchannel_logout_session_required": frontchannel_logout_session_required,
            "backchannel_logout_uri": backchannel_logout_uri,
            "backchannel_logout_session_required": backchannel_logout_session_required,
            "available_to_all": available_to_all,
            "logo_uri": logo_uri,
            "client_uri": client_uri,
            "policy_uri": policy_uri,
            "tos_uri": tos_uri,
            "initiate_login_uri": initiate_login_uri,
            "device_grant_enabled": device_grant_enabled,
            "is_public": is_public,
            "registration_metadata": Json(registration_metadata),
            "registration_access_token_hash": registration_access_token_hash,
            "registered_with_token_id": registered_with_token_id,
        },
    )
    assert client is not None  # INSERT ... RETURNING always returns a row
    if not is_public:
        client["client_secret"] = client_secret
    return client


def replace_registered_client(
    tenant_id: TenantArg,
    client_id: str,
    *,
    name: str,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str],
    frontchannel_logout_uri: str | None,
    frontchannel_logout_session_required: bool,
    backchannel_logout_uri: str | None,
    backchannel_logout_session_required: bool,
    logo_uri: str | None,
    client_uri: str | None,
    policy_uri: str | None,
    tos_uri: str | None,
    initiate_login_uri: str | None,
    registration_metadata: dict,
    device_grant_enabled: bool = False,
) -> dict | None:
    """Replace a dynamically registered client's metadata (RFC 7592 section 2.2).

    Credentials (and whether the client is public), access settings, and the
    registration bookkeeping are left alone. Only rows marked
    ``dynamically_registered`` are touched.
    """
    return fetchone(
        tenant_id,
        f"""
        update oauth2_clients set
            name = :name,
            redirect_uris = :redirect_uris,
            post_logout_redirect_uris = :post_logout_redirect_uris,
            frontchannel_logout_uri = :frontchannel_logout_uri,
            frontchannel_logout_session_required = :frontchannel_logout_session_required,
            backchannel_logout_uri = :backchannel_logout_uri,
            backchannel_logout_session_required = :backchannel_logout_session_required,
            logo_uri = :logo_uri,
            client_uri = :client_uri,
            policy_uri = :policy_uri,
            tos_uri = :tos_uri,
            initiate_login_uri = :initiate_login_uri,
            device_grant_enabled = :device_grant_enabled,
            registration_metadata = :registration_metadata
        where client_id = :client_id and dynamically_registered
        returning {_CLIENT_COLUMNS}
        """,
        {
            "client_id": client_id,
            "name": name,
            "redirect_uris": redirect_uris,
            "post_logout_redirect_uris": post_logout_redirect_uris,
            "frontchannel_logout_uri": frontchannel_logout_uri,
            "frontchannel_logout_session_required": frontchannel_logout_session_required,
            "backchannel_logout_uri": backchannel_logout_uri,
            "backchannel_logout_session_required": backchannel_logout_session_required,
            "logo_uri": logo_uri,
            "client_uri": client_uri,
            "policy_uri": policy_uri,
            "tos_uri": tos_uri,
            "initiate_login_uri": initiate_login_uri,
            "device_grant_enabled": device_grant_enabled,
            "registration_metadata": Json(registration_metadata),
        },
    )
