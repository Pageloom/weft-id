"""OIDC upstream connection CRUD operations.

Mirrors ``services.saml.providers`` for the consuming (relying-party)
direction of OIDC: list, get, create, update, delete, enable/disable, and
set-default. The client secret is encrypted at rest (reversible) via a
purpose-specific Fernet key and is never returned from any read path --
responses expose a ``client_secret_set`` boolean instead.
"""

import logging
from typing import Any

import database
from cryptography.fernet import Fernet
from schemas.oidc_upstream import (
    OIDCConnectionConfig,
    OIDCConnectionCreate,
    OIDCConnectionListItem,
    OIDCConnectionListResponse,
    OIDCConnectionUpdate,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.oidc_upstream.presets import (
    compose_entra_authority,
    compose_entra_discovery_url,
    get_preset_defaults,
)
from services.types import RequestingUser
from utils.crypto import derive_fernet_key

logger = logging.getLogger(__name__)

# Purpose-specific Fernet key for the OIDC upstream client secret. Distinct
# from the SAML private-key key so a compromise of one purpose does not
# expose the other.
_cipher = Fernet(derive_fernet_key(b"oidc-upstream-client-secret"))


def _encrypt_secret(plaintext: str) -> str:
    """Encrypt a client secret for storage at rest."""
    return _cipher.encrypt(plaintext.encode()).decode()


def decrypt_client_secret(encrypted: str) -> str:
    """Decrypt a client secret read from storage.

    Used by the auth flow (Iteration 3) to authenticate outbound token
    exchanges. The plaintext never leaves the service layer.
    """
    return _cipher.decrypt(encrypted.encode()).decode()


def _row_to_config(row: dict, base_url: str) -> OIDCConnectionConfig:
    """Convert a database row to an OIDCConnectionConfig schema."""
    connection_id = str(row["id"])
    return OIDCConnectionConfig(
        id=connection_id,
        name=row["name"],
        provider_type=row["provider_type"],
        issuer=row["issuer"],
        discovery_url=row.get("discovery_url"),
        authorization_endpoint=row.get("authorization_endpoint"),
        token_endpoint=row.get("token_endpoint"),
        userinfo_endpoint=row.get("userinfo_endpoint"),
        jwks_uri=row.get("jwks_uri"),
        discovery_fetched_at=row.get("discovery_fetched_at"),
        discovery_error=row.get("discovery_error"),
        client_id=row.get("client_id"),
        client_secret_set=bool(row.get("client_secret_enc")),
        scopes=row.get("scopes"),
        claim_mapping=row["claim_mapping"],
        correlation_claim=row["correlation_claim"],
        group_claim_source=row.get("group_claim_source"),
        hosted_domain=row.get("hosted_domain"),
        entra_tenant_id=row.get("entra_tenant_id"),
        is_enabled=row["is_enabled"],
        is_default=row["is_default"],
        require_platform_mfa=row["require_platform_mfa"],
        jit_provisioning=row["jit_provisioning"],
        allow_email_linking=row["allow_email_linking"],
        callback_url=f"{base_url}/auth/oidc/{connection_id}/callback",
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_list_item(row: dict) -> OIDCConnectionListItem:
    """Convert a database row to an OIDCConnectionListItem schema."""
    return OIDCConnectionListItem(
        id=str(row["id"]),
        name=row["name"],
        provider_type=row["provider_type"],
        is_enabled=row["is_enabled"],
        is_default=row["is_default"],
        discovery_url=row.get("discovery_url"),
        discovery_fetched_at=row.get("discovery_fetched_at"),
        discovery_error=row.get("discovery_error"),
        created_at=row["created_at"],
    )


def list_connections(
    requesting_user: RequestingUser,
) -> OIDCConnectionListResponse:
    """List all OIDC connections for the tenant.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.oidc_upstream.list_connections(requesting_user["tenant_id"])
    items = [_row_to_list_item(row) for row in rows]

    return OIDCConnectionListResponse(items=items, total=len(items))


def get_connection(
    requesting_user: RequestingUser,
    connection_id: str,
    base_url: str,
) -> OIDCConnectionConfig:
    """Get a single OIDC connection configuration.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    row = database.oidc_upstream.get_connection(requesting_user["tenant_id"], connection_id)
    if row is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    return _row_to_config(row, base_url)


def get_connection_row(tenant_id: str, connection_id: str) -> dict | None:
    """Fetch a raw connection row for the public auth path.

    No authorization check: this is used by the login/callback flow, which
    runs before a user is authenticated. Returns the raw database row (or
    ``None``) so the router never touches the database layer directly.
    """
    return database.oidc_upstream.get_connection(tenant_id, connection_id)


def oidc_connection_requires_platform_mfa(tenant_id: str, connection_id: str) -> bool:
    """Check if an OIDC connection requires platform MFA after authentication.

    Internal helper for the auth flow. No authorization check because this
    only returns a single boolean flag.
    """
    row = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if row is None:
        return False
    return bool(row.get("require_platform_mfa", False))


def _apply_preset_defaults(data: OIDCConnectionCreate) -> OIDCConnectionCreate:
    """Fill unset fields from the provider preset so the API and non-JS form
    paths receive the same defaults the browser form pre-fills.

    The preset registry defines per-provider defaults (scopes, correlation
    claim, issuer/discovery URL). These were previously applied only by the
    form's client-side JS, so an API-created connection (or a form submitted
    with JS disabled) silently fell back to ``sub`` correlation and no scopes.
    This makes the service layer the single source of truth.

    For Entra, the issuer/discovery URL are composed from ``entra_tenant_id``
    when the admin did not supply an explicit issuer.
    """
    defaults = get_preset_defaults(data.provider_type)
    if not defaults:
        return data

    # correlation_claim: when the caller left it unset, use the preset's claim
    # (Entra -> "oid"); otherwise fall back to "sub". An explicit caller value
    # is always respected.
    if data.correlation_claim is None:
        data.correlation_claim = defaults.get("correlation_claim") or "sub"

    if not data.scopes and defaults.get("scopes"):
        data.scopes = defaults["scopes"]

    if not data.issuer and defaults.get("issuer"):
        data.issuer = defaults["issuer"]

    if not data.discovery_url and defaults.get("discovery_url"):
        data.discovery_url = defaults["discovery_url"]

    # Entra composes its authority from the tenant id when no explicit issuer
    # was supplied.
    if data.provider_type == "entra" and not data.issuer and data.entra_tenant_id:
        data.issuer = compose_entra_authority(data.entra_tenant_id)
        if not data.discovery_url:
            data.discovery_url = compose_entra_discovery_url(data.entra_tenant_id)

    # Generic has no preset issuer; it must be supplied explicitly.
    if data.provider_type == "generic" and not data.issuer:
        raise ValidationError(
            message="issuer is required for a generic OIDC connection",
            code="oidc_connection_issuer_required",
        )

    return data


def create_connection(
    requesting_user: RequestingUser,
    data: OIDCConnectionCreate,
    base_url: str,
) -> OIDCConnectionConfig:
    """Create a new OIDC connection.

    Authorization: Requires super_admin role.
    Logs: oidc_idp_connection_created event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    data = _apply_preset_defaults(data)

    # _apply_preset_defaults guarantees a non-None issuer (composed from the
    # preset or tenant id, or rejected for generic) and a non-None
    # correlation_claim (preset claim or "sub").
    issuer = data.issuer
    correlation_claim = data.correlation_claim
    assert issuer is not None
    assert correlation_claim is not None

    client_secret_enc = None
    if data.client_secret:
        client_secret_enc = _encrypt_secret(data.client_secret)

    row = database.oidc_upstream.create_connection(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=data.name,
        provider_type=data.provider_type,
        issuer=issuer,
        created_by=requesting_user["id"],
        discovery_url=data.discovery_url,
        authorization_endpoint=data.authorization_endpoint,
        token_endpoint=data.token_endpoint,
        userinfo_endpoint=data.userinfo_endpoint,
        jwks_uri=data.jwks_uri,
        client_id=data.client_id,
        client_secret_enc=client_secret_enc,
        scopes=data.scopes,
        claim_mapping=data.claim_mapping,
        correlation_claim=correlation_claim,
        group_claim_source=data.group_claim_source,
        hosted_domain=data.hosted_domain,
        entra_tenant_id=data.entra_tenant_id,
        is_enabled=data.is_enabled,
        is_default=data.is_default,
        require_platform_mfa=data.require_platform_mfa,
        jit_provisioning=data.jit_provisioning,
        allow_email_linking=data.allow_email_linking,
    )

    if row is None:
        raise ValidationError(
            message="Failed to create OIDC connection",
            code="oidc_connection_creation_failed",
        )

    connection_id = str(row["id"])

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type="oidc_idp_connection_created",
        metadata={
            "name": data.name,
            "provider_type": data.provider_type,
            "issuer": data.issuer,
        },
    )

    return _row_to_config(row, base_url)


def update_connection(
    requesting_user: RequestingUser,
    connection_id: str,
    data: OIDCConnectionUpdate,
    base_url: str,
) -> OIDCConnectionConfig:
    """Update an existing OIDC connection.

    Authorization: Requires super_admin role.
    Logs: oidc_idp_connection_updated event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    existing = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if existing is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    update_kwargs: dict[str, Any] = {}
    for field in [
        "name",
        "issuer",
        "discovery_url",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "client_id",
        "scopes",
        "claim_mapping",
        "correlation_claim",
        "group_claim_source",
        "hosted_domain",
        "entra_tenant_id",
        "require_platform_mfa",
        "jit_provisioning",
        "allow_email_linking",
    ]:
        value = getattr(data, field, None)
        if value is not None:
            update_kwargs[field] = value

    # The client secret is handled separately: it is write-only and encrypted.
    if data.client_secret is not None:
        update_kwargs["client_secret_enc"] = _encrypt_secret(data.client_secret)

    if not update_kwargs:
        return _row_to_config(existing, base_url)

    row = database.oidc_upstream.update_connection(tenant_id, connection_id, **update_kwargs)

    if row is None:
        raise ValidationError(
            message="Failed to update OIDC connection",
            code="oidc_connection_update_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type="oidc_idp_connection_updated",
        metadata={"updated_fields": list(update_kwargs.keys())},
    )

    return _row_to_config(row, base_url)


def delete_connection(
    requesting_user: RequestingUser,
    connection_id: str,
) -> None:
    """Delete an OIDC connection.

    Authorization: Requires super_admin role.
    Logs: oidc_idp_connection_deleted event.

    Security: Cannot delete if enabled, or if users are linked. Before the
    delete, canonical ``user_attributes`` rows whose value still matches this
    connection's last-mirrored snapshot are scrubbed (``cause:
    idp_disconnect_scrub``), mirroring the SAML delete path.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    existing = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if existing is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    if existing.get("is_enabled"):
        raise ConflictError(
            message="Cannot delete an enabled OIDC connection. Disable it first.",
            code="oidc_connection_is_enabled",
        )

    link_count = database.oidc_upstream.count_links_for_connection(tenant_id, connection_id)
    if link_count > 0:
        raise ConflictError(
            message=(
                f"Cannot delete OIDC connection: {link_count} user(s) are linked to it. "
                "Unlink users first."
            ),
            code="oidc_connection_has_linked_users",
            details={"link_count": link_count, "connection_id": connection_id},
        )

    # Disconnect scrub: clear canonical user_attributes rows whose value still
    # matches this connection's last-mirrored snapshot, so the deleted
    # connection's attributes stop flowing to downstream SPs. Must run before
    # the delete because the cascade wipes the mirror rows.
    from services.oidc_upstream.attributes import scrub_oidc_canonical_matches_mirror

    scrubbed_count = scrub_oidc_canonical_matches_mirror(
        tenant_id=tenant_id,
        idp_id=connection_id,
        actor_user_id=requesting_user["id"],
    )

    database.oidc_upstream.delete_connection(tenant_id, connection_id)

    # Drop any cached JWKS for the deleted connection so its keys are not
    # retained in memory.
    from services.oidc_upstream.jwks import clear_jwks_cache

    clear_jwks_cache(tenant_id, connection_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type="oidc_idp_connection_deleted",
        metadata={"name": existing["name"], "scrubbed_count": scrubbed_count},
    )


def set_connection_enabled(
    requesting_user: RequestingUser,
    connection_id: str,
    enabled: bool,
    base_url: str,
) -> OIDCConnectionConfig:
    """Enable or disable an OIDC connection.

    Authorization: Requires super_admin role.
    Logs: oidc_idp_connection_enabled or oidc_idp_connection_disabled event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    existing = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if existing is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    row = database.oidc_upstream.set_connection_enabled(tenant_id, connection_id, enabled)

    if row is None:
        raise ValidationError(
            message="Failed to update OIDC connection",
            code="oidc_connection_update_failed",
        )

    event_type = "oidc_idp_connection_enabled" if enabled else "oidc_idp_connection_disabled"
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type=event_type,
        metadata={"name": existing["name"]},
    )

    return _row_to_config(row, base_url)


def get_claim_mapping(
    requesting_user: RequestingUser,
    connection_id: str,
) -> dict[str, str]:
    """Return a connection's claim mapping (OIDC claim -> WeftID attribute).

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    row = database.oidc_upstream.get_connection(requesting_user["tenant_id"], connection_id)
    if row is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )
    return row.get("claim_mapping") or {}


def update_claim_mapping(
    requesting_user: RequestingUser,
    connection_id: str,
    claim_mapping: dict[str, str],
    base_url: str,
) -> OIDCConnectionConfig:
    """Replace a connection's claim mapping, dropping unknown attribute keys.

    The mapping is ``{weftid_attribute: oidc_claim}``. Keys outside the fixed
    set (email/first_name/last_name) or the 14-attribute standard registry are
    dropped so the mirror writer never sees an unknown key.

    Authorization: Requires super_admin role.
    Logs: oidc_idp_connection_updated event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    from constants.user_attributes import is_standard_attribute

    fixed = frozenset({"email", "first_name", "last_name"})
    filtered = {
        key: value
        for key, value in claim_mapping.items()
        if key in fixed or is_standard_attribute(key)
    }

    return update_connection(
        requesting_user,
        connection_id,
        OIDCConnectionUpdate(claim_mapping=filtered),
        base_url,
    )


def set_connection_default(
    requesting_user: RequestingUser,
    connection_id: str,
    base_url: str,
) -> OIDCConnectionConfig:
    """Set an OIDC connection as the default for the tenant.

    Authorization: Requires super_admin role.
    Logs: oidc_idp_connection_set_default event.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    existing = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if existing is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    row = database.oidc_upstream.set_connection_default(tenant_id, connection_id)

    if row is None:
        raise ValidationError(
            message="Failed to update OIDC connection",
            code="oidc_connection_update_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type="oidc_idp_connection_set_default",
        metadata={"name": existing["name"]},
    )

    return _row_to_config(row, base_url)
