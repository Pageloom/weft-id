"""Privileged domain management.

Handles domain CRUD, domain-group links for auto-assignment,
and domain utility queries used by other services.
"""

import logging

import database
from schemas.settings import (
    DomainGroupLink,
    DomainGroupLinkCreate,
    PrivilegedDomain,
    PrivilegedDomainCreate,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser

log = logging.getLogger(__name__)


# =============================================================================
# Domain Validation Helpers (private)
# =============================================================================


def _normalize_domain(domain: str) -> str:
    """Normalize domain input: strip, lowercase, remove @ prefix."""
    domain = domain.strip().lower()
    if domain.startswith("@"):
        domain = domain[1:]
    return domain


def _validate_domain_format(domain: str) -> None:
    """Validate domain format. Raises ValidationError if invalid."""
    if not domain:
        raise ValidationError(
            message="Domain cannot be empty",
            code="invalid_domain",
            field="domain",
        )
    if " " in domain:
        raise ValidationError(
            message="Domain cannot contain spaces",
            code="invalid_domain",
            field="domain",
        )
    if "." not in domain:
        raise ValidationError(
            message="Domain must contain at least one dot",
            code="invalid_domain",
            field="domain",
        )
    if len(domain) < 3 or len(domain) > 253:
        raise ValidationError(
            message="Domain must be 3-253 characters",
            code="invalid_domain_length",
            field="domain",
        )


def _domain_row_to_model(
    row: dict, linked_groups: list[DomainGroupLink] | None = None
) -> PrivilegedDomain:
    """Convert database row to PrivilegedDomain model."""
    created_by_name = None
    if row.get("first_name") or row.get("last_name"):
        created_by_name = f"{row.get('first_name', '')} {row.get('last_name', '')}".strip()

    return PrivilegedDomain(
        id=str(row["id"]),
        domain=row["domain"],
        created_at=row["created_at"],
        created_by_name=created_by_name,
        bound_idp_id=str(row["bound_idp_id"]) if row.get("bound_idp_id") else None,
        bound_idp_name=row.get("bound_idp_name"),
        linked_groups=linked_groups or [],
    )


def _link_row_to_model(row: dict) -> DomainGroupLink:
    """Convert database row to DomainGroupLink model."""
    created_by_name = None
    if row.get("first_name") or row.get("last_name"):
        created_by_name = f"{row.get('first_name', '')} {row.get('last_name', '')}".strip()

    return DomainGroupLink(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        group_id=str(row["group_id"]),
        group_name=row["group_name"],
        created_at=row["created_at"],
        created_by_name=created_by_name,
    )


# =============================================================================
# Privileged Domains
# =============================================================================


def list_privileged_domains(
    requesting_user: RequestingUser,
) -> list[PrivilegedDomain]:
    """
    List all privileged domains for the tenant.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request

    Returns:
        List of PrivilegedDomain objects

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    rows = database.settings.list_privileged_domains(tenant_id)

    # Enrich with linked groups
    link_rows = database.settings.get_all_domain_group_links(tenant_id)
    links_by_domain: dict[str, list[DomainGroupLink]] = {}
    for lr in link_rows:
        domain_id = str(lr["domain_id"])
        links_by_domain.setdefault(domain_id, []).append(_link_row_to_model(lr))

    return [_domain_row_to_model(row, links_by_domain.get(str(row["id"]), [])) for row in rows]


def add_privileged_domain(
    requesting_user: RequestingUser,
    domain_data: PrivilegedDomainCreate,
) -> PrivilegedDomain:
    """
    Add a new privileged domain.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_data: The domain to add

    Returns:
        The created PrivilegedDomain

    Raises:
        ForbiddenError: If user lacks admin permissions
        ValidationError: If domain format is invalid
        ConflictError: If domain already exists
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Normalize and validate
    domain_clean = _normalize_domain(domain_data.domain)
    _validate_domain_format(domain_clean)

    # Check for conflicts
    if database.settings.privileged_domain_exists(tenant_id, domain_clean):
        raise ConflictError(
            message=f"Domain '{domain_clean}' already exists",
            code="domain_exists",
            details={"domain": domain_clean},
        )

    # Create the domain
    database.settings.add_privileged_domain(
        tenant_id=tenant_id,
        domain=domain_clean,
        created_by=requesting_user["id"],
        tenant_id_value=tenant_id,
    )

    # Fetch and return the created domain
    rows = database.settings.list_privileged_domains(tenant_id)
    for row in rows:
        if row["domain"] == domain_clean:
            # Log the event
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="privileged_domain",
                artifact_id=str(row["id"]),
                event_type="privileged_domain_added",
                metadata={"domain": domain_clean},
            )
            return _domain_row_to_model(row)

    # Should not happen, but handle gracefully
    raise ValidationError(
        message="Failed to retrieve created domain",
        code="domain_creation_failed",
    )


def delete_privileged_domain(
    requesting_user: RequestingUser,
    domain_id: str,
) -> None:
    """
    Delete a privileged domain.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_id: UUID of the domain to delete

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If domain does not exist
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify domain exists and capture info for logging
    rows = database.settings.list_privileged_domains(tenant_id)
    domain_row = None
    for row in rows:
        if str(row["id"]) == domain_id:
            domain_row = row
            break

    if not domain_row:
        raise NotFoundError(
            message="Domain not found",
            code="domain_not_found",
            details={"domain_id": domain_id},
        )

    database.settings.delete_privileged_domain(tenant_id, domain_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="privileged_domain",
        artifact_id=domain_id,
        event_type="privileged_domain_deleted",
        metadata={"domain": domain_row["domain"]},
    )


# =============================================================================
# Domain-Group Links
# =============================================================================


def list_domain_group_links(
    requesting_user: RequestingUser,
    domain_id: str,
) -> list[DomainGroupLink]:
    """
    List group links for a privileged domain.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_id: UUID of the privileged domain

    Returns:
        List of DomainGroupLink objects

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If domain does not exist
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify domain exists
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if not domain:
        raise NotFoundError(
            message="Domain not found",
            code="domain_not_found",
            details={"domain_id": domain_id},
        )

    rows = database.settings.get_domain_group_links(tenant_id, domain_id)
    return [_link_row_to_model(row) for row in rows]


def add_domain_group_link(
    requesting_user: RequestingUser,
    domain_id: str,
    link_data: DomainGroupLinkCreate,
) -> DomainGroupLink:
    """
    Link a group to a privileged domain for auto-assignment.

    When created, retroactively adds existing users with verified emails
    matching the domain to the linked group.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_id: UUID of the privileged domain
        link_data: Contains group_id to link

    Returns:
        The created DomainGroupLink

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If domain or group does not exist
        ValidationError: If group is not a weftid group
        ConflictError: If link already exists
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify domain exists
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if not domain:
        raise NotFoundError(
            message="Domain not found",
            code="domain_not_found",
            details={"domain_id": domain_id},
        )

    # Verify group exists and is weftid type
    group = database.groups.get_group_by_id(tenant_id, link_data.group_id)
    if not group:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
            details={"group_id": link_data.group_id},
        )
    if group["group_type"] != "weftid":
        raise ValidationError(
            message="Only WeftID groups can be linked to domains. "
            "IdP groups are managed by the identity provider.",
            code="invalid_group_type",
            field="group_id",
        )

    # Create the link
    result = database.settings.add_domain_group_link(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        group_id=link_data.group_id,
        created_by=requesting_user["id"],
    )

    if not result:
        raise ConflictError(
            message="This group is already linked to this domain",
            code="link_exists",
            details={"domain_id": domain_id, "group_id": link_data.group_id},
        )

    # Log the link creation event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="domain_group_link",
        artifact_id=str(result["id"]),
        event_type="domain_group_link_created",
        metadata={
            "domain": domain["domain"],
            "group_id": link_data.group_id,
            "group_name": group["name"],
        },
    )

    # Retroactively process existing users with verified emails on this domain
    users = database.users.get_users_by_email_domain(tenant_id, domain["domain"])
    if users:
        user_ids = [str(u["id"]) for u in users]
        added = database.groups.bulk_add_group_members(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            group_id=link_data.group_id,
            user_ids=user_ids,
        )
        if added > 0:
            log.info(
                "Retroactively added %d users to group '%s' for domain '%s'",
                added,
                group["name"],
                domain["domain"],
            )
            for user_id in user_ids:
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=requesting_user["id"],
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="domain_group_auto_assigned",
                    metadata={
                        "domain": domain["domain"],
                        "groups": [group["name"]],
                    },
                )

    # Fetch and return the created link
    link_rows = database.settings.get_domain_group_links(tenant_id, domain_id)
    for lr in link_rows:
        if str(lr["id"]) == str(result["id"]):
            return _link_row_to_model(lr)

    # Should not happen
    raise ValidationError(
        message="Failed to retrieve created link",
        code="link_creation_failed",
    )


def delete_domain_group_link(
    requesting_user: RequestingUser,
    domain_id: str,
    link_id: str,
) -> None:
    """
    Unlink a group from a privileged domain.

    Does NOT remove existing group memberships (they are regular memberships).

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_id: UUID of the privileged domain
        link_id: UUID of the link to delete

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If link does not exist
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify the link exists and belongs to this domain
    link = database.settings.get_domain_group_link_by_id(tenant_id, link_id)
    if not link or str(link["domain_id"]) != domain_id:
        raise NotFoundError(
            message="Link not found",
            code="link_not_found",
            details={"link_id": link_id},
        )

    database.settings.delete_domain_group_link(tenant_id, link_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="domain_group_link",
        artifact_id=link_id,
        event_type="domain_group_link_deleted",
        metadata={
            "group_id": str(link["group_id"]),
            "group_name": link["group_name"],
        },
    )


# =============================================================================
# Auto-Assignment Utility
# =============================================================================


def auto_assign_user_to_domain_groups(
    tenant_id: str,
    user_id: str,
    email: str,
    actor_user_id: str | None = None,
) -> int:
    """
    Auto-assign a user to groups linked to their email domain.

    This is a utility function without authorization, called from user
    creation and email verification hooks.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to add to groups
        email: User's email address (domain is extracted)
        actor_user_id: Who triggered this (for audit log). Defaults to user_id.

    Returns:
        Number of new group memberships created
    """
    if not email or "@" not in email:
        return 0

    domain = email.split("@", 1)[1].lower()
    linked = database.settings.get_group_ids_for_domain(tenant_id, domain)
    if not linked:
        return 0

    actor = actor_user_id or user_id
    total_added = 0
    added_group_names: list[str] = []

    for link in linked:
        result = database.groups.add_group_member(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            group_id=str(link["group_id"]),
            user_id=user_id,
        )
        if result:
            total_added += 1
            added_group_names.append(link["group_name"])

    if total_added > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor,
            artifact_type="user",
            artifact_id=user_id,
            event_type="domain_group_auto_assigned",
            metadata={
                "domain": domain,
                "groups": added_group_names,
            },
        )

    return total_added


# =============================================================================
# Domain Utility Queries
# =============================================================================


def get_privileged_domains_list(tenant_id: str) -> list[str]:
    """
    Get list of privileged domain names for a tenant.

    This is a utility function that does not require authorization,
    intended for use by other services (e.g., when creating users).

    Args:
        tenant_id: The tenant ID

    Returns:
        List of domain strings (e.g., ["example.com", "corp.example.com"])
    """
    rows = database.settings.list_privileged_domains(tenant_id)
    return [row["domain"] for row in rows]


def is_privileged_domain(tenant_id: str, domain: str) -> bool:
    """
    Check if a domain is privileged for the tenant.

    This is a utility function that does not require authorization.

    Args:
        tenant_id: The tenant ID
        domain: Domain to check

    Returns:
        True if domain is privileged, False otherwise
    """
    return database.settings.privileged_domain_exists(tenant_id, domain.lower())
