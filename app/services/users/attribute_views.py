"""View-builder helpers for tenant attribute rendering on profile templates.

These functions compose data from the tenant attribute config, the user's
canonical attribute values, and (for the admin IdP-mirror panel) the
per-IdP snapshot rows into structures the templates can render
directly. They live in the service layer because they reach into both
``services.settings`` and ``database`` (for the IdP display-name lookup)
and orchestrate read calls across multiple service surfaces.

Used by:

* ``app/routers/account.py`` -- self-service profile page.
* ``app/routers/users/detail.py`` -- admin user-detail profile + IdP-mirror tab.

The functions deliberately swallow ``ServiceError`` (the underlying
read failures) into empty results so the rest of the profile page can
still render when a transient read fails. Hard failures are not the
caller's concern here.
"""

from __future__ import annotations

import database
from constants.user_attributes import CATEGORIES, STANDARD_ATTRIBUTES
from services import settings as settings_service
from services.activity import track_activity
from services.exceptions import ServiceError
from services.types import RequestingUser

_CATEGORY_LABELS: dict[str, str] = {
    "contact": "Contact",
    "professional": "Professional",
    "location": "Location",
    "profile": "Profile",
}


def _build_groups(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> tuple[dict[str, dict], dict[str, str]]:
    """Internal helper returning (config_by_key, values_by_key).

    Both dicts are empty if the underlying service calls fail; the caller
    decides whether that's a hard error or a soft "render the rest of the
    page anyway" condition. The current call sites all opt for soft.
    """
    try:
        config_rows = settings_service.list_tenant_attribute_config(requesting_user)
    except ServiceError:
        config_rows = []
    config_by_key = {row["attribute_key"]: row for row in config_rows}

    # Late import via the package so test patches against
    # ``services.users.list_user_attributes`` propagate here.
    from services import users as users_service

    try:
        attribute_rows = users_service.list_user_attributes(requesting_user, target_user_id)
    except ServiceError:
        attribute_rows = []
    values_by_key = {row["attribute_key"]: row["value"] for row in attribute_rows}

    return config_by_key, values_by_key


def build_attribute_groups_for_self(
    requesting_user: RequestingUser,
) -> list[dict]:
    """Return enabled tenant attributes grouped by category, with values.

    Self-service variant: locked attributes are surfaced with ``locked=True``
    so the template can render them read-only. Disabled attributes are
    filtered out (they are not in scope for this tenant).
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    config_by_key, values_by_key = _build_groups(requesting_user, requesting_user["id"])

    grouped: list[dict] = []
    for category in CATEGORIES:
        items = []
        for attr in STANDARD_ATTRIBUTES:
            if attr.category != category:
                continue
            cfg = config_by_key.get(attr.key)
            if not cfg or not cfg.get("enabled"):
                continue
            items.append(
                {
                    "key": attr.key,
                    "label": attr.default_friendly_name,
                    "category": attr.category,
                    "value_type": attr.value_type,
                    "max_length": attr.max_length,
                    "value": values_by_key.get(attr.key, ""),
                    "required": bool(cfg.get("required")),
                    "locked": bool(cfg.get("locked_for_users")),
                }
            )
        if items:
            grouped.append(
                {
                    "key": category,
                    "label": _CATEGORY_LABELS.get(category, category.title()),
                    "attributes": items,
                }
            )
    return grouped


def build_attribute_groups_for_admin(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> list[dict]:
    """Return enabled tenant attributes grouped by category, with values.

    Admin variant: every enabled attribute is editable here regardless of
    lock state. The lock flag is still surfaced so the template can show
    a small indicator next to admin-only attributes. ``mirror_from_idp``
    is also surfaced so the template can label rows the IdP will refill.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    config_by_key, values_by_key = _build_groups(requesting_user, target_user_id)

    grouped: list[dict] = []
    for category in CATEGORIES:
        items = []
        for attr in STANDARD_ATTRIBUTES:
            if attr.category != category:
                continue
            cfg = config_by_key.get(attr.key)
            if not cfg or not cfg.get("enabled"):
                continue
            items.append(
                {
                    "key": attr.key,
                    "label": attr.default_friendly_name,
                    "category": attr.category,
                    "value_type": attr.value_type,
                    "max_length": attr.max_length,
                    "value": values_by_key.get(attr.key, ""),
                    "required": bool(cfg.get("required")),
                    "locked": bool(cfg.get("locked_for_users")),
                    "mirror_from_idp": bool(cfg.get("mirror_from_idp")),
                }
            )
        if items:
            grouped.append(
                {
                    "key": category,
                    "label": _CATEGORY_LABELS.get(category, category.title()),
                    "attributes": items,
                }
            )
    return grouped


def build_idp_attribute_panel(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> list[dict]:
    """Return IdP-mirror snapshot rows grouped by IdP for the admin panel.

    Each group has the IdP id, the IdP display name, and a list of
    ``{attribute_key, value, updated_at, mirrored_into_profile}`` rows.
    The ``mirrored_into_profile`` flag reflects the tenant's current
    ``mirror_from_idp`` config so admins see at a glance which rows are
    already in the canonical store.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Late import via the package so test patches propagate.
    from services import users as users_service

    try:
        rows = users_service.list_user_idp_attributes(requesting_user, target_user_id)
    except ServiceError:
        return []
    if not rows:
        return []

    # Tenant-level mirror flag per attribute key.
    try:
        config_rows = settings_service.list_tenant_attribute_config(requesting_user)
    except ServiceError:
        config_rows = []
    mirror_by_key = {row["attribute_key"]: bool(row.get("mirror_from_idp")) for row in config_rows}

    # Per-IdP display name lookup. The reads are scoped to the same
    # tenant by RLS; missing IdPs are tagged "Unknown IdP" defensively.
    idp_lookup: dict[str, str] = {}

    grouped: list[dict] = []
    by_idp: dict[str, list[dict]] = {}
    for row in rows:
        idp_id = str(row["idp_id"])
        if idp_id not in idp_lookup:
            idp = database.saml.get_identity_provider(requesting_user["tenant_id"], idp_id)
            idp_lookup[idp_id] = idp["name"] if idp else "Unknown IdP"
        by_idp.setdefault(idp_id, []).append(
            {
                "attribute_key": row["attribute_key"],
                "value": row["value"],
                "updated_at": row["updated_at"],
                "mirrored_into_profile": mirror_by_key.get(row["attribute_key"], False),
            }
        )

    for idp_id, items in by_idp.items():
        grouped.append(
            {
                "idp_id": idp_id,
                "idp_name": idp_lookup.get(idp_id, "Unknown IdP"),
                "attributes": items,
            }
        )
    return grouped
