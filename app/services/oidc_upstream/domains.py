"""OIDC upstream domain binding operations.

Mirrors ``services.saml.domains`` for the consuming (relying-party)
direction of OIDC: bind/unbind/rebind privileged domains to OIDC connections
and list bindings. A domain binds to at most one IdP across BOTH protocols;
the cross-protocol exclusivity is enforced here (the DB UNIQUE constraint
only spans the OIDC table).

Unlike SAML, binding a domain to an OIDC connection does NOT retroactively
assign existing users: OIDC correlates users on the ``(idp_id, sub)`` link
table, not on ``users.saml_idp_id``, and there is no per-user OIDC assignment
column. Binding only affects the routing of *unknown* users (JIT) and the
login flow. The ``user_oidc_idp_assigned`` event is therefore emitted only
when a user is actually linked during the auth flow, not on domain bind.
"""

import logging

import database
from schemas.oidc_upstream import (
    OIDCDomainBinding,
    OIDCDomainBindingList,
    OIDCUnboundDomain,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def _binding_row_to_model(row: dict, domain: str) -> OIDCDomainBinding:
    """Convert a binding row + domain name to an OIDCDomainBinding schema."""
    return OIDCDomainBinding(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        domain=domain,
        idp_id=str(row["idp_id"]),
        created_at=row["created_at"],
    )


def list_domain_bindings(
    requesting_user: RequestingUser,
    connection_id: str,
) -> OIDCDomainBindingList:
    """List domains bound to a specific OIDC connection.

    Authorization: Requires super_admin role.
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

    rows = database.oidc_upstream.get_domain_bindings_for_connection(tenant_id, connection_id)
    items = [
        OIDCDomainBinding(
            id=str(row["id"]),
            domain_id=str(row["domain_id"]),
            domain=row["domain"],
            idp_id=str(row["idp_id"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]

    return OIDCDomainBindingList(items=items)


def bind_domain_to_connection(
    requesting_user: RequestingUser,
    connection_id: str,
    domain_id: str,
) -> OIDCDomainBinding:
    """Bind a privileged domain to an OIDC connection.

    Authorization: Requires super_admin role.
    Logs: oidc_domain_bound event.

    A domain binds to at most one IdP across both protocols. If the domain is
    already bound to a SAML IdP, this raises a ConflictError.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    connection = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if connection is None:
        raise NotFoundError(
            message="OIDC connection not found",
            code="oidc_connection_not_found",
        )

    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    # Cross-protocol exclusivity: a domain cannot be bound to a SAML IdP and an
    # OIDC connection at the same time. The DB UNIQUE constraint only spans the
    # OIDC table, so check the SAML binding table explicitly.
    saml_binding = database.saml.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if saml_binding is not None:
        raise ConflictError(
            message=(
                f"Domain '{domain['domain']}' is already bound to a SAML identity "
                "provider. Unbind it from the SAML IdP first."
            ),
            code="domain_bound_to_saml_idp",
            details={"domain_id": domain_id, "saml_idp_id": str(saml_binding["idp_id"])},
        )

    row = database.oidc_upstream.bind_domain_to_connection(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        connection_id=connection_id,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to bind domain to OIDC connection",
            code="domain_binding_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_domain_binding",
        artifact_id=str(row["id"]),
        event_type="oidc_domain_bound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "idp_id": connection_id,
            "idp_name": connection["name"],
        },
    )

    return _binding_row_to_model(row, domain["domain"])


def unbind_domain_from_connection(
    requesting_user: RequestingUser,
    domain_id: str,
) -> None:
    """Unbind a domain from its OIDC connection.

    Authorization: Requires super_admin role.
    Logs: oidc_domain_unbound event.

    This only removes the binding record. Users already linked to the
    connection keep their links; new users with this domain are no longer
    routed to the connection.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    binding = database.oidc_upstream.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if binding is None:
        raise NotFoundError(
            message="Domain binding not found",
            code="domain_binding_not_found",
        )

    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    database.oidc_upstream.unbind_domain_from_connection(tenant_id, domain_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_domain_binding",
        artifact_id=str(binding["id"]),
        event_type="oidc_domain_unbound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "previous_idp_id": str(binding["idp_id"]),
        },
    )


def rebind_domain_to_connection(
    requesting_user: RequestingUser,
    domain_id: str,
    new_connection_id: str,
) -> OIDCDomainBinding:
    """Rebind a domain from one OIDC connection to another.

    Authorization: Requires super_admin role.
    Logs: oidc_domain_rebound event.

    Existing user links are preserved (they are keyed on the old connection's
    id); only the routing of unknown users changes.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    current_binding = database.oidc_upstream.get_domain_binding_by_domain_id(tenant_id, domain_id)
    if current_binding is None:
        raise NotFoundError(
            message="Domain binding not found",
            code="domain_binding_not_found",
        )

    new_connection = database.oidc_upstream.get_connection(tenant_id, new_connection_id)
    if new_connection is None:
        raise NotFoundError(
            message="Target OIDC connection not found",
            code="oidc_connection_not_found",
        )

    domain = database.settings.get_privileged_domain_by_id(tenant_id, domain_id)
    if domain is None:
        raise NotFoundError(
            message="Privileged domain not found",
            code="domain_not_found",
        )

    previous_idp_id = str(current_binding["idp_id"])

    row = database.oidc_upstream.bind_domain_to_connection(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        domain_id=domain_id,
        connection_id=new_connection_id,
        created_by=requesting_user["id"],
    )

    if row is None:
        raise ValidationError(
            message="Failed to rebind domain",
            code="domain_rebind_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_domain_binding",
        artifact_id=str(row["id"]),
        event_type="oidc_domain_rebound",
        metadata={
            "domain": domain["domain"],
            "domain_id": domain_id,
            "previous_idp_id": previous_idp_id,
            "new_idp_id": new_connection_id,
            "new_idp_name": new_connection["name"],
        },
    )

    return _binding_row_to_model(row, domain["domain"])


def get_unbound_domains(
    requesting_user: RequestingUser,
) -> list[OIDCUnboundDomain]:
    """Get privileged domains not bound to any OIDC connection.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.oidc_upstream.get_unbound_domains(requesting_user["tenant_id"])

    return [
        OIDCUnboundDomain(
            id=str(row["id"]),
            domain=row["domain"],
        )
        for row in rows
    ]
