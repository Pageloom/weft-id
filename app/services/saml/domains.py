"""Domain binding and user IdP assignment operations.

This module handles:
- Binding privileged domains to IdPs
- Unbinding/rebinding domains
- Manual user IdP assignment
"""

import logging

import database
import services.groups as groups_service
from schemas.saml import DomainBinding, DomainBindingList, UnboundDomain
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


# ============================================================================
# Domain Binding Operations
# ============================================================================


def list_domain_bindings(
    requesting_user: RequestingUser,
    idp_id: str,
) -> DomainBindingList:
    """
    List domains bound to a specific IdP.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user
        idp_id: IdP UUID to list bindings for

    Returns:
        DomainBindingList with bound domains
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    rows = database.saml.get_domain_bindings_for_idp(tenant_id, idp_id)
    items = [
        DomainBinding(
            id=str(row["id"]),
            domain_id=str(row["domain_id"]),
            domain=row["domain"],
            idp_id=str(row["idp_id"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]

    return DomainBindingList(items=items)


def bind_domain_to_idp(
    requesting_user: RequestingUser,
    idp_id: str,
    domain_id: str,
) -> DomainBinding:
    """
    Bind a privileged domain to an IdP and assign all matching users.

    Immediately assigns all users with verified emails in this domain
    to the IdP and wipes their passwords. This is a permanent assignment.

    Authorization: Requires super_admin role.
    Logs: saml_domain_bound event + user_saml_idp_assigned for each user.

    Args:
        requesting_user: The authenticated user
        idp_id: IdP UUID to bind domain to
        domain_id: Privileged domain UUID to bind

    Returns:
        Created DomainBinding
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    idp = database.saml.get_identity_provider(tenant_id, idp_id)
    if idp is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    # Verify domain exists
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    # Get all users with emails in this domain who don't already have this IdP
    users_in_domain = database.users.get_users_by_email_domain(tenant_id, domain["domain"])
    users_to_assign = [
        u
        for u in users_in_domain
        if u.get("saml_idp_id") is None or str(u["saml_idp_id"]) != idp_id
    ]

    # Assign all matching users to this IdP (wipes passwords)
    user_ids_to_assign = [str(u["id"]) for u in users_to_assign]
    if user_ids_to_assign:
        database.users.bulk_assign_users_to_idp(tenant_id, user_ids_to_assign, idp_id)
        groups_service.ensure_users_in_base_group(
            tenant_id, user_ids_to_assign, idp_id, idp["name"]
        )
        logger.info(
            f"Domain binding: assigned {len(user_ids_to_assign)} users "
            f"from {domain['domain']} to IdP {idp['name']}"
        )

    # Create binding (upsert - replaces existing binding if any)
    row = database.saml.bind_domain_to_idp(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        idp_id=idp_id,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to bind domain to IdP",
            code="domain_binding_failed",
        )

    # Log domain binding event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_domain_binding",
        artifact_id=str(row["id"]),
        event_type="saml_domain_bound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "idp_id": idp_id,
            "idp_name": idp["name"],
            "users_assigned": len(user_ids_to_assign),
        },
    )

    # Log individual user assignments
    for user_id in user_ids_to_assign:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_saml_idp_assigned",
            metadata={
                "saml_idp_id": idp_id,
                "idp_name": idp["name"],
                "assigned_via": "domain_binding",
                "domain": domain["domain"],
                "password_wiped": False,
            },
        )

    return DomainBinding(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        domain=domain["domain"],
        idp_id=str(row["idp_id"]),
        created_at=row["created_at"],
    )


def unbind_domain_from_idp(
    requesting_user: RequestingUser,
    domain_id: str,
) -> None:
    """
    Unbind a domain from its IdP.

    This only removes the domain binding record. Users who were assigned
    to the IdP via this binding keep their IdP assignments (they were
    explicitly assigned when the domain was bound).

    New users with this domain will no longer be auto-assigned to the IdP.

    Authorization: Requires super_admin role.
    Logs: saml_domain_unbound event.

    Args:
        requesting_user: The authenticated user
        domain_id: Domain UUID to unbind
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get the binding
    binding = database.saml.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if binding is None:
        raise NotFoundError(
            message="Domain binding not found",
            code="domain_binding_not_found",
        )

    # Get the domain for logging
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    database.saml.unbind_domain_from_idp(tenant_id, domain_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_domain_binding",
        artifact_id=str(binding["id"]),
        event_type="saml_domain_unbound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "previous_idp_id": str(binding["idp_id"]),
        },
    )


def rebind_domain_to_idp(
    requesting_user: RequestingUser,
    domain_id: str,
    new_idp_id: str,
) -> DomainBinding:
    """
    Rebind a domain from one IdP to another, moving all affected users.

    Users with emails in this domain who are currently assigned to the
    old IdP are reassigned to the new IdP.

    Authorization: Requires super_admin role.
    Logs: saml_domain_rebound event + user_saml_idp_assigned for each moved user.

    Args:
        requesting_user: The authenticated user
        domain_id: Domain UUID to rebind
        new_idp_id: New IdP UUID to bind to

    Returns:
        Updated DomainBinding
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get the current binding
    current_binding = database.saml.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if current_binding is None:
        raise NotFoundError(
            message="Domain binding not found",
            code="domain_binding_not_found",
        )

    # Verify new IdP exists
    new_idp = database.saml.get_identity_provider(tenant_id, new_idp_id)
    if new_idp is None:
        raise NotFoundError(
            message="Target identity provider not found",
            code="idp_not_found",
        )

    # Get domain info
    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    previous_idp_id = str(current_binding["idp_id"])

    # Get previous IdP name for group operations
    previous_idp = database.saml.get_identity_provider(tenant_id, previous_idp_id)
    previous_idp_name = previous_idp["name"] if previous_idp else "Unknown"

    # Find users with this domain who are currently on the old IdP
    users_in_domain = database.users.get_users_by_email_domain(tenant_id, domain["domain"])
    users_to_move = [
        u
        for u in users_in_domain
        if u.get("saml_idp_id") is not None and str(u["saml_idp_id"]) == previous_idp_id
    ]

    # Move users to new IdP (they already have no passwords from original binding)
    user_ids_to_move = [str(u["id"]) for u in users_to_move]
    if user_ids_to_move:
        # Use bulk update - no need to wipe passwords (already wiped)
        for user_id in user_ids_to_move:
            database.users.update_user_saml_idp(tenant_id, user_id, new_idp_id)

        # Move group memberships: remove from old IdP groups, add to new base group
        groups_service.move_users_between_idps(
            tenant_id,
            user_ids_to_move,
            previous_idp_id,
            previous_idp_name,
            new_idp_id,
            new_idp["name"],
        )

        logger.info(
            f"Domain rebind: moved {len(user_ids_to_move)} users "
            f"from IdP {previous_idp_id} to {new_idp['name']}"
        )

    # Update binding (upsert handles the update)
    row = database.saml.bind_domain_to_idp(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        idp_id=new_idp_id,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to rebind domain",
            code="domain_rebind_failed",
        )

    # Log domain rebind event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_domain_binding",
        artifact_id=str(row["id"]),
        event_type="saml_domain_rebound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "previous_idp_id": previous_idp_id,
            "new_idp_id": new_idp_id,
            "new_idp_name": new_idp["name"],
            "users_moved": len(user_ids_to_move),
        },
    )

    # Log individual user moves
    for user_id in user_ids_to_move:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_saml_idp_assigned",
            metadata={
                "saml_idp_id": new_idp_id,
                "idp_name": new_idp["name"],
                "assigned_via": "domain_rebind",
                "domain": domain["domain"],
                "previous_idp_id": previous_idp_id,
            },
        )

    return DomainBinding(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        domain=domain["domain"],
        idp_id=str(row["idp_id"]),
        created_at=row["created_at"],
    )


def get_unbound_domains(
    requesting_user: RequestingUser,
) -> list[UnboundDomain]:
    """
    Get privileged domains not bound to any IdP.

    Authorization: Requires super_admin role.

    Returns:
        List of UnboundDomain
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.saml.get_unbound_domains(requesting_user["tenant_id"])

    return [
        UnboundDomain(
            id=str(row["id"]),
            domain=row["domain"],
        )
        for row in rows
    ]


# ============================================================================
# User IdP Assignment
# ============================================================================


def assign_user_idp(
    requesting_user: RequestingUser,
    user_id: str,
    saml_idp_id: str | None,
) -> None:
    """
    Assign a user to an IdP or set them as a password-only user.

    Every user must be either:
    - Password user (saml_idp_id = NULL) - authenticates with password
    - IdP user (saml_idp_id = UUID) - authenticates via SAML

    Security constraints:
    - If assigning to IdP: wipe password (keep MFA)
    - If removing from IdP (setting to NULL): inactivate + unverify emails

    Authorization: Requires super_admin role.
    Logs: user_saml_idp_assigned event.

    Args:
        requesting_user: The authenticated user
        user_id: User UUID to update
        saml_idp_id: IdP UUID to assign, or None for password-only
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get current user state
    user = database.users.get_user_with_saml_info(tenant_id, user_id)
    if user is None:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    # Verify IdP exists if specified
    idp_name = None
    if saml_idp_id is not None:
        idp = database.saml.get_identity_provider(tenant_id, saml_idp_id)
        if idp is None:
            raise NotFoundError(
                message="Identity provider not found",
                code="idp_not_found",
            )
        idp_name = idp["name"]

    current_idp_id = user.get("saml_idp_id")

    # Determine state changes
    had_idp = current_idp_id is not None
    will_have_idp = saml_idp_id is not None

    # Log password status when assigning to IdP
    if will_have_idp and user.get("has_password"):
        logger.info(f"User {user_id} assigned to IdP (password preserved)")
    elif will_have_idp:
        logger.warning(f"User {user_id} assigned to IdP without password")

    # Security: Inactivate + unverify when removing from IdP (not when moving to another)
    user_inactivated = False
    if had_idp and not will_have_idp:
        database.users.unverify_user_emails(tenant_id, user_id)
        database.users.inactivate_user(tenant_id, user_id)
        database.oauth2.revoke_all_user_tokens(tenant_id, user_id)
        user_inactivated = True
        logger.info(f"User {user_id} inactivated after being removed from IdP")

    # Update user's IdP assignment
    database.users.update_user_saml_idp(
        tenant_id=tenant_id,
        user_id=user_id,
        saml_idp_id=saml_idp_id,
    )

    # Update group memberships based on IdP change
    user_email = user.get("email", "")
    if had_idp and will_have_idp and str(current_idp_id) != saml_idp_id:
        # Moving between IdPs: remove from all old IdP groups, add to new base group
        old_idp = database.saml.get_identity_provider(tenant_id, str(current_idp_id))
        old_idp_name = old_idp["name"] if old_idp else "Unknown"
        groups_service.remove_user_from_all_idp_groups(
            tenant_id, user_id, user_email, str(current_idp_id), old_idp_name
        )
        assert saml_idp_id is not None and idp_name is not None
        groups_service.ensure_user_in_base_group(
            tenant_id, user_id, user_email, saml_idp_id, idp_name
        )
    elif will_have_idp and not had_idp:
        # New assignment: add to base group
        assert saml_idp_id is not None and idp_name is not None
        groups_service.ensure_user_in_base_group(
            tenant_id, user_id, user_email, saml_idp_id, idp_name
        )
    elif had_idp and not will_have_idp:
        # Removing from IdP: remove from all old IdP groups
        old_idp = database.saml.get_identity_provider(tenant_id, str(current_idp_id))
        old_idp_name = old_idp["name"] if old_idp else "Unknown"
        groups_service.remove_user_from_all_idp_groups(
            tenant_id, user_id, user_email, str(current_idp_id), old_idp_name
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_saml_idp_assigned",
        metadata={
            "saml_idp_id": saml_idp_id,
            "idp_name": idp_name,
            "previous_idp_id": str(current_idp_id) if current_idp_id else None,
            "password_wiped": False,
            "user_inactivated": user_inactivated,
        },
    )
