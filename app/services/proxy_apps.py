"""Proxy-app (forward-auth) management service.

A proxy app is an HTTP application behind a verified protected domain that WeftID
gates as a forward-auth authority. This service owns the CRUD for proxy apps and
their group grants, with validation and audit logging.

Authorization is super_admin: proxy apps are infrastructure config under the
Service Providers section, parallel to SAML SP management and protected domains.

A proxy app may only be created against a *verified* protected domain (mirroring
the verified-gate the Caddy ask endpoint and TenantGuardMiddleware already apply).
Group grants reuse the shared sp_group_assignments table via the proxy_app_id FK,
so one access path serves SAML SPs and proxy apps.
"""

import logging
from urllib.parse import urlsplit

import database
from schemas.proxy_apps import (
    SUPPORTED_HEADER_KEYS,
    ProxyApp,
    ProxyAppCreate,
    ProxyAppGrant,
    ProxyAppGrantList,
    ProxyAppList,
    ProxyAppUpdate,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.types import RequestingUser

log = logging.getLogger(__name__)


# =============================================================================
# Validation helpers (private)
# =============================================================================


def _normalize_host(value: str) -> str:
    """Normalize a host: strip, lowercase, drop trailing dot."""
    return value.strip().lower().rstrip(".")


def _validate_external_url(external_url: str, domain: str) -> str:
    """Validate the external URL: well-formed https whose host is under *domain*.

    Returns the normalized URL. Raises ValidationError if malformed.
    """
    url = external_url.strip()
    if not url:
        raise ValidationError(
            message="The external URL cannot be empty.",
            code="invalid_external_url",
            field="external_url",
        )

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValidationError(
            message="The external URL must use https.",
            code="invalid_external_url_scheme",
            field="external_url",
        )
    if not parts.hostname:
        raise ValidationError(
            message="The external URL must include a hostname.",
            code="invalid_external_url",
            field="external_url",
        )

    host = _normalize_host(parts.hostname)
    if host != domain and not host.endswith(f".{domain}"):
        raise ValidationError(
            message=(f"The external URL host must be under the protected domain ({domain})."),
            code="external_url_not_under_domain",
            field="external_url",
        )
    return url


def _validate_public_paths(public_paths: list[str]) -> list[str]:
    """Validate public paths: each is a rooted relative pattern (starts with '/').

    Returns the cleaned list. Raises ValidationError if any path is invalid.
    """
    cleaned: list[str] = []
    for raw in public_paths:
        path = raw.strip()
        if not path:
            continue
        if not path.startswith("/"):
            raise ValidationError(
                message=f"Public path '{path}' must start with '/'.",
                code="invalid_public_path",
                field="public_paths",
            )
        if path.startswith("//"):
            raise ValidationError(
                message=f"Public path '{path}' must be a rooted relative path, not a URL.",
                code="invalid_public_path",
                field="public_paths",
            )
        if "://" in path or " " in path:
            raise ValidationError(
                message=f"Public path '{path}' must be a rooted relative path pattern.",
                code="invalid_public_path",
                field="public_paths",
            )
        cleaned.append(path)
    return cleaned


def _validate_header_config(header_config: dict[str, bool]) -> dict[str, bool]:
    """Validate header config: keys restricted to the supported X-Forwarded-* set.

    Returns the cleaned dict (booleans coerced). Raises ValidationError on an
    unsupported key.
    """
    cleaned: dict[str, bool] = {}
    for key, value in header_config.items():
        if key not in SUPPORTED_HEADER_KEYS:
            raise ValidationError(
                message=(
                    f"Unsupported header config key '{key}'. Allowed keys: "
                    f"{', '.join(sorted(SUPPORTED_HEADER_KEYS))}."
                ),
                code="invalid_header_config",
                field="header_config",
            )
        cleaned[key] = bool(value)
    return cleaned


def _row_to_model(
    row: dict,
    domain: str | None = None,
    created_by_name: str | None = None,
) -> ProxyApp:
    """Convert a proxy_apps row to a ProxyApp model."""
    public_paths = row.get("public_paths") or []
    header_config = row.get("header_config") or {}
    return ProxyApp(
        id=str(row["id"]),
        protected_domain_id=str(row["protected_domain_id"]),
        domain=domain,
        name=row["name"],
        external_url=row["external_url"],
        description=row.get("description"),
        public_paths=list(public_paths),
        header_config=dict(header_config),
        available_to_all=row["available_to_all"],
        enabled=row["enabled"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        created_by_name=created_by_name,
    )


def _created_by_name(tenant_id: str, created_by: object) -> str | None:
    """Resolve a created_by user id to a display name, if available."""
    if not created_by:
        return None
    user = database.users.get_user_by_id(tenant_id, str(created_by))
    if not user:
        return None
    name = f"{user.get('first_name', '') or ''} {user.get('last_name', '') or ''}".strip()
    return name or user.get("email")


def _domain_for(tenant_id: str, protected_domain_id: object) -> str | None:
    """Resolve a protected_domain_id to its domain string, if available."""
    if not protected_domain_id:
        return None
    row = database.protected_domains.get_protected_domain(tenant_id, str(protected_domain_id))
    return row["domain"] if row else None


def _require_verified_domain(tenant_id: str, protected_domain_id: str) -> dict:
    """Fetch a protected domain and require it be verified. Raises on failure."""
    domain_row = database.protected_domains.get_protected_domain(tenant_id, protected_domain_id)
    if not domain_row:
        raise NotFoundError(
            message="Protected domain not found.",
            code="protected_domain_not_found",
            details={"protected_domain_id": protected_domain_id},
        )
    if domain_row["verification_status"] != "verified":
        raise ValidationError(
            message=("The protected domain must be verified before you can add a proxy app to it."),
            code="protected_domain_not_verified",
            field="protected_domain_id",
        )
    return domain_row


# =============================================================================
# CRUD (super_admin-authz)
# =============================================================================


def list_proxy_apps(requesting_user: RequestingUser) -> ProxyAppList:
    """List all proxy apps for the tenant.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    rows = database.proxy_apps.list_proxy_apps(tenant_id)
    # Resolve domains in one pass via a small cache.
    domain_cache: dict[str, str | None] = {}
    items: list[ProxyApp] = []
    for row in rows:
        domain_id = str(row["protected_domain_id"])
        if domain_id not in domain_cache:
            domain_cache[domain_id] = _domain_for(tenant_id, domain_id)
        items.append(
            _row_to_model(
                row,
                domain=domain_cache[domain_id],
                created_by_name=_created_by_name(tenant_id, row.get("created_by")),
            )
        )
    return ProxyAppList(items=items, total=len(items))


def get_proxy_app(requesting_user: RequestingUser, proxy_app_id: str) -> ProxyApp:
    """Get a single proxy app by ID.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the app does not exist for this tenant.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    row = database.proxy_apps.get_proxy_app(tenant_id, proxy_app_id)
    if not row:
        raise NotFoundError(
            message="Proxy app not found.",
            code="proxy_app_not_found",
            details={"proxy_app_id": proxy_app_id},
        )
    return _row_to_model(
        row,
        domain=_domain_for(tenant_id, row["protected_domain_id"]),
        created_by_name=_created_by_name(tenant_id, row.get("created_by")),
    )


def create_proxy_app(requesting_user: RequestingUser, data: ProxyAppCreate) -> ProxyApp:
    """Create a proxy app under a verified protected domain.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the protected domain does not exist.
        ValidationError: If the domain is unverified or any field is malformed.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    domain_row = _require_verified_domain(tenant_id, data.protected_domain_id)
    domain = domain_row["domain"]

    external_url = _validate_external_url(data.external_url, domain)
    public_paths = _validate_public_paths(data.public_paths)
    header_config = _validate_header_config(data.header_config)

    row = database.proxy_apps.create_proxy_app(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        protected_domain_id=data.protected_domain_id,
        name=data.name.strip(),
        external_url=external_url,
        created_by=requesting_user["id"],
        description=(data.description.strip() if data.description else None),
        public_paths=public_paths,
        header_config=header_config,
        available_to_all=data.available_to_all,
        enabled=data.enabled,
    )
    if not row:
        raise ValidationError(
            message="Failed to create proxy app.",
            code="proxy_app_create_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="proxy_app_created",
        artifact_type="proxy_app",
        artifact_id=str(row["id"]),
        metadata={"name": row["name"], "domain": domain, "external_url": external_url},
    )

    return _row_to_model(
        row,
        domain=domain,
        created_by_name=_created_by_name(tenant_id, row.get("created_by")),
    )


def update_proxy_app(
    requesting_user: RequestingUser, proxy_app_id: str, data: ProxyAppUpdate
) -> ProxyApp:
    """Update a proxy app's mutable fields.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the app does not exist for this tenant.
        ValidationError: If any provided field is malformed.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    existing = database.proxy_apps.get_proxy_app(tenant_id, proxy_app_id)
    if not existing:
        raise NotFoundError(
            message="Proxy app not found.",
            code="proxy_app_not_found",
            details={"proxy_app_id": proxy_app_id},
        )

    domain = _domain_for(tenant_id, existing["protected_domain_id"])

    updates: dict[str, object] = {}
    if data.name is not None:
        updates["name"] = data.name.strip()
    if data.description is not None:
        updates["description"] = data.description.strip() or None
    if data.external_url is not None:
        if domain is None:
            raise ValidationError(
                message="Cannot validate the external URL: owning domain is missing.",
                code="proxy_app_domain_missing",
                field="external_url",
            )
        updates["external_url"] = _validate_external_url(data.external_url, domain)
    if data.public_paths is not None:
        updates["public_paths"] = _validate_public_paths(data.public_paths)
    if data.header_config is not None:
        updates["header_config"] = _validate_header_config(data.header_config)
    if data.available_to_all is not None:
        updates["available_to_all"] = data.available_to_all
    if data.enabled is not None:
        updates["enabled"] = data.enabled

    row = database.proxy_apps.update_proxy_app(tenant_id, proxy_app_id, **updates)
    if not row:
        raise NotFoundError(
            message="Proxy app not found.",
            code="proxy_app_not_found",
            details={"proxy_app_id": proxy_app_id},
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="proxy_app_updated",
        artifact_type="proxy_app",
        artifact_id=proxy_app_id,
        metadata={"name": row["name"], "fields": sorted(updates.keys())},
    )

    return _row_to_model(
        row,
        domain=domain,
        created_by_name=_created_by_name(tenant_id, row.get("created_by")),
    )


def delete_proxy_app(requesting_user: RequestingUser, proxy_app_id: str) -> None:
    """Delete a proxy app (cascades to its group grants).

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the app does not exist for this tenant.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    row = database.proxy_apps.get_proxy_app(tenant_id, proxy_app_id)
    if not row:
        raise NotFoundError(
            message="Proxy app not found.",
            code="proxy_app_not_found",
            details={"proxy_app_id": proxy_app_id},
        )

    database.proxy_apps.delete_proxy_app(tenant_id, proxy_app_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="proxy_app_deleted",
        artifact_type="proxy_app",
        artifact_id=proxy_app_id,
        metadata={"name": row["name"]},
    )


# =============================================================================
# Group grants (super_admin-authz)
# =============================================================================


def _require_proxy_app(tenant_id: str, proxy_app_id: str) -> dict:
    """Fetch a proxy app or raise NotFoundError."""
    row = database.proxy_apps.get_proxy_app(tenant_id, proxy_app_id)
    if not row:
        raise NotFoundError(
            message="Proxy app not found.",
            code="proxy_app_not_found",
            details={"proxy_app_id": proxy_app_id},
        )
    return row


def list_proxy_app_grants(requesting_user: RequestingUser, proxy_app_id: str) -> ProxyAppGrantList:
    """List group grants for a proxy app.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    _require_proxy_app(tenant_id, proxy_app_id)

    rows = database.sp_group_assignments.list_assignments_for_proxy_app(tenant_id, proxy_app_id)
    items = [
        ProxyAppGrant(
            id=str(row["id"]),
            proxy_app_id=str(row["proxy_app_id"]),
            group_id=str(row["group_id"]),
            group_name=row["group_name"],
            group_description=row.get("group_description"),
            group_type=row["group_type"],
            assigned_by=str(row["assigned_by"]),
            assigned_at=row["assigned_at"],
        )
        for row in rows
    ]
    return ProxyAppGrantList(items=items, total=len(items))


def list_available_groups_for_proxy_app(
    requesting_user: RequestingUser, proxy_app_id: str
) -> list[dict]:
    """List groups not yet granted to a proxy app (for the assign dropdown).

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    _require_proxy_app(tenant_id, proxy_app_id)

    all_groups = database.groups.list_groups(tenant_id)
    assigned = database.sp_group_assignments.list_assignments_for_proxy_app(tenant_id, proxy_app_id)
    assigned_ids = {str(row["group_id"]) for row in assigned}
    return [
        {"id": str(g["id"]), "name": g["name"], "group_type": g["group_type"]}
        for g in all_groups
        if str(g["id"]) not in assigned_ids
    ]


def add_proxy_app_grant(
    requesting_user: RequestingUser, proxy_app_id: str, group_id: str
) -> ProxyAppGrant:
    """Grant a group access to a proxy app.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the app or group does not exist.
        ConflictError: If the group is already granted.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    app_row = _require_proxy_app(tenant_id, proxy_app_id)

    group_row = database.groups.get_group_by_id(tenant_id, group_id)
    if group_row is None:
        raise NotFoundError(message="Group not found.", code="group_not_found")

    # Pre-check for an existing grant: the DB enforces a partial unique index and
    # would raise UniqueViolation, but we surface a clean ConflictError instead.
    existing = database.sp_group_assignments.list_assignments_for_proxy_app(tenant_id, proxy_app_id)
    if any(str(r["group_id"]) == group_id for r in existing):
        raise ConflictError(
            message="Group is already granted access to this proxy app.",
            code="proxy_app_grant_exists",
        )

    row = database.sp_group_assignments.create_proxy_app_assignment(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        proxy_app_id=proxy_app_id,
        group_id=group_id,
        assigned_by=requesting_user["id"],
    )
    if row is None:
        raise ConflictError(
            message="Group is already granted access to this proxy app.",
            code="proxy_app_grant_exists",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="proxy_app_grant_added",
        artifact_type="proxy_app",
        artifact_id=proxy_app_id,
        metadata={
            "group_id": group_id,
            "group_name": group_row["name"],
            "proxy_app_name": app_row["name"],
        },
    )

    return ProxyAppGrant(
        id=str(row["id"]),
        proxy_app_id=str(row["proxy_app_id"]),
        group_id=str(row["group_id"]),
        group_name=group_row["name"],
        group_description=group_row.get("description"),
        group_type=group_row["group_type"],
        assigned_by=str(row["assigned_by"]),
        assigned_at=row["assigned_at"],
    )


def remove_proxy_app_grant(
    requesting_user: RequestingUser, proxy_app_id: str, group_id: str
) -> None:
    """Remove a group grant from a proxy app.

    Authorization: Requires super_admin role.

    Raises:
        NotFoundError: If the app or grant does not exist.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    app_row = _require_proxy_app(tenant_id, proxy_app_id)

    deleted = database.sp_group_assignments.delete_proxy_app_assignment(
        tenant_id, proxy_app_id, group_id
    )
    if deleted == 0:
        raise NotFoundError(
            message="Group grant not found.",
            code="proxy_app_grant_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        event_type="proxy_app_grant_removed",
        artifact_type="proxy_app",
        artifact_id=proxy_app_id,
        metadata={"group_id": group_id, "proxy_app_name": app_row["name"]},
    )
