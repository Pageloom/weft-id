"""Authentication routing logic for SAML SSO.

This module determines the authentication route for a user based on their
email address, checking IdP assignments, domain bindings, and JIT provisioning.
"""

import database
from schemas.saml import AuthRouteResult


def determine_auth_route(
    tenant_id: str,
    email: str,
) -> AuthRouteResult:
    """
    Determine authentication route for an email address.

    Used during email-first login flow to decide whether to show
    password form or redirect to IdP.

    Every user is either:
    - Password user (saml_idp_id = NULL) → route to password form
    - IdP user (saml_idp_id = UUID) → route to that IdP

    For unknown users:
    - If domain is bound to IdP with JIT → route to domain's IdP
    - If default IdP has JIT → route to default IdP
    - Otherwise → not found

    Args:
        tenant_id: Tenant ID
        email: Email address to check

    Returns:
        AuthRouteResult with route_type and optional idp info
    """
    # Extract domain from email
    if "@" not in email:
        return AuthRouteResult(
            route_type="invalid_email",
        )

    email_domain = email.split("@")[1].lower()

    # Look up user
    user = database.users.get_user_auth_info(tenant_id, email)

    if user is not None:
        user_id = str(user["id"])

        # Check if user is inactivated
        if user.get("is_inactivated"):
            return AuthRouteResult(
                route_type="inactivated",
                user_id=user_id,
            )

        # User has IdP assigned → route to that IdP
        if user.get("saml_idp_id"):
            idp = database.saml.get_identity_provider(tenant_id, str(user["saml_idp_id"]))
            if idp and idp.get("is_enabled"):
                return AuthRouteResult(
                    route_type="idp",
                    idp_id=str(user["saml_idp_id"]),
                    idp_name=idp["name"],
                    user_id=user_id,
                )
            else:
                # IdP exists but disabled - user can't authenticate
                return AuthRouteResult(
                    route_type="idp_disabled",
                    user_id=user_id,
                )

        # User has password → route to password form
        if user.get("has_password"):
            return AuthRouteResult(
                route_type="password",
                user_id=user_id,
            )

        # User exists but has no password and no IdP - should not happen
        # but handle gracefully
        return AuthRouteResult(
            route_type="no_auth_method",
            user_id=user_id,
        )

    # User doesn't exist - check for JIT provisioning routes

    # Domain bound to IdP with JIT enabled
    domain_idp = database.saml.get_idp_for_domain(tenant_id, email_domain)
    if domain_idp and domain_idp.get("is_enabled") and domain_idp.get("jit_provisioning"):
        return AuthRouteResult(
            route_type="idp_jit",
            idp_id=str(domain_idp["id"]),
            idp_name=domain_idp["name"],
        )

    # Tenant default IdP with JIT enabled
    default_idp = database.saml.get_default_identity_provider(tenant_id)
    if default_idp and default_idp.get("is_enabled") and default_idp.get("jit_provisioning"):
        return AuthRouteResult(
            route_type="idp_jit",
            idp_id=str(default_idp["id"]),
            idp_name=default_idp["name"],
        )

    # No user and no JIT route
    return AuthRouteResult(
        route_type="not_found",
    )
