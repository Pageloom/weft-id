"""Protocol-neutral authentication routing logic.

``determine_auth_route`` was originally SAML-only (``services.saml.routing``).
As OIDC upstream IdPs became binding targets (Iteration 6), the decision point
gained OIDC route types, so it moved to this protocol-neutral home.
``services.saml.routing`` re-exports it for backwards compatibility.

Resolution order is explicit and tested:

1. Invalid email → ``invalid_email``.
2. Known user:
   - inactivated → ``inactivated``
   - SAML IdP assigned → ``idp`` / ``idp_disabled``
   - OIDC link → ``idp_oidc`` / ``idp_oidc_disabled``
   - password → ``password``
   - otherwise → ``no_auth_method``
3. Unknown user (JIT routes):
   - SAML domain binding (JIT) → ``idp_jit``
   - OIDC domain binding (JIT) → ``idp_oidc_jit``
   - SAML default IdP (JIT) → ``idp_jit``
   - OIDC default connection (JIT) → ``idp_oidc_jit``
   - otherwise → ``not_found``

SAML and OIDC identity are mutually exclusive per user: a user with
``saml_idp_id`` set is routed to SAML before any OIDC link is consulted, and
vice versa. A user cannot resolve to both.
"""

import database
from schemas.auth_routing import AuthRouteResult


def determine_auth_route(
    tenant_id: str,
    email: str,
) -> AuthRouteResult:
    """Determine the authentication route for an email address.

    Used during the email-first login flow to decide whether to show the
    password form or redirect to a SAML IdP / OIDC connection.

    Args:
        tenant_id: Tenant ID.
        email: Email address to check.

    Returns:
        AuthRouteResult with route_type and optional idp info.
    """
    if "@" not in email:
        return AuthRouteResult(route_type="invalid_email")

    email_domain = email.split("@")[1].lower()

    user = database.users.get_user_auth_info(tenant_id, email)

    if user is not None:
        user_id = str(user["id"])

        if user.get("is_inactivated"):
            return AuthRouteResult(route_type="inactivated", user_id=user_id)

        # SAML identity takes precedence when both are present (a user with a
        # SAML assignment is a SAML user; OIDC links are only consulted for
        # users without a SAML assignment).
        if user.get("saml_idp_id"):
            idp = database.saml.get_identity_provider(tenant_id, str(user["saml_idp_id"]))
            if idp and idp.get("is_enabled"):
                return AuthRouteResult(
                    route_type="idp",
                    idp_id=str(user["saml_idp_id"]),
                    idp_name=idp["name"],
                    user_id=user_id,
                )
            return AuthRouteResult(route_type="idp_disabled", user_id=user_id)

        # OIDC link: a user with an oidc_idp_user_links row is an OIDC user.
        oidc_link = database.oidc_upstream.get_link_for_user(tenant_id, user_id)
        if oidc_link is not None:
            connection = database.oidc_upstream.get_connection(tenant_id, str(oidc_link["idp_id"]))
            if connection and connection.get("is_enabled"):
                return AuthRouteResult(
                    route_type="idp_oidc",
                    idp_id=str(connection["id"]),
                    idp_name=connection["name"],
                    user_id=user_id,
                )
            return AuthRouteResult(route_type="idp_oidc_disabled", user_id=user_id)

        if user.get("has_password"):
            return AuthRouteResult(route_type="password", user_id=user_id)

        return AuthRouteResult(route_type="no_auth_method", user_id=user_id)

    # Unknown user - check JIT provisioning routes.

    # SAML domain binding (JIT).
    domain_idp = database.saml.get_idp_for_domain(tenant_id, email_domain)
    if domain_idp and domain_idp.get("is_enabled") and domain_idp.get("jit_provisioning"):
        return AuthRouteResult(
            route_type="idp_jit",
            idp_id=str(domain_idp["id"]),
            idp_name=domain_idp["name"],
        )

    # OIDC domain binding (JIT).
    domain_connection = database.oidc_upstream.get_connection_for_domain(tenant_id, email_domain)
    if (
        domain_connection
        and domain_connection.get("is_enabled")
        and domain_connection.get("jit_provisioning")
    ):
        return AuthRouteResult(
            route_type="idp_oidc_jit",
            idp_id=str(domain_connection["id"]),
            idp_name=domain_connection["name"],
        )

    # SAML default IdP (JIT).
    default_idp = database.saml.get_default_identity_provider(tenant_id)
    if default_idp and default_idp.get("is_enabled") and default_idp.get("jit_provisioning"):
        return AuthRouteResult(
            route_type="idp_jit",
            idp_id=str(default_idp["id"]),
            idp_name=default_idp["name"],
        )

    # OIDC default connection (JIT).
    default_connection = database.oidc_upstream.get_default_connection(tenant_id)
    if (
        default_connection
        and default_connection.get("is_enabled")
        and default_connection.get("jit_provisioning")
    ):
        return AuthRouteResult(
            route_type="idp_oidc_jit",
            idp_id=str(default_connection["id"]),
            idp_name=default_connection["name"],
        )

    return AuthRouteResult(route_type="not_found")
