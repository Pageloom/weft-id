"""Validation guards for groups service.

These private helpers enforce business rules for group operations.
"""

import database
from services.exceptions import ForbiddenError


def _is_idp_group(group: dict) -> bool:
    """Check if a group is managed by an IdP (read-only)."""
    return group.get("group_type") == "idp"


def _require_not_idp_group(group: dict, operation: str) -> None:
    """Raise ForbiddenError if trying to modify an IdP-managed group."""
    if _is_idp_group(group):
        raise ForbiddenError(
            message=f"Cannot {operation}: this group is managed by an identity provider",
            code="idp_group_readonly",
        )


def _idp_source_ref(group: dict) -> tuple[str, str] | None:
    """Return ``(source, provider_id)`` for an IdP group, or None.

    ``source`` is ``"saml"`` when the group hangs off ``idp_id`` and
    ``"oidc"`` when it hangs off ``oidc_connection_id``. Non-IdP groups and
    IdP groups with no source (orphaned) return None.
    """
    if not _is_idp_group(group):
        return None
    if group.get("idp_id"):
        return ("saml", str(group["idp_id"]))
    if group.get("oidc_connection_id"):
        return ("oidc", str(group["oidc_connection_id"]))
    return None


def _is_idp_umbrella_group(tenant_id: str, group: dict) -> bool:
    """Check if a group is the umbrella (base) group for its IdP.

    The umbrella group has the same name as the IdP and serves as the root
    of the IdP group hierarchy.
    """
    ref = _idp_source_ref(group)
    if ref is None:
        return False
    source, provider_id = ref
    base_group_id = database.groups.get_idp_base_group_id(tenant_id, provider_id, source)
    return base_group_id is not None and str(group.get("id")) == base_group_id


def _is_idp_managed_relationship(tenant_id: str, parent: dict, child: dict) -> bool:
    """Check if a parent-child relationship is managed by the IdP system.

    Returns True when parent is the umbrella group for an IdP and child is
    an IdP group of the same IdP. These relationships are created automatically
    during authentication and should not be removed manually.
    """
    parent_ref = _idp_source_ref(parent)
    child_ref = _idp_source_ref(child)
    if parent_ref is None or child_ref is None or parent_ref != child_ref:
        return False
    return _is_idp_umbrella_group(tenant_id, parent)
