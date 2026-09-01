"""Protocol-neutral authentication routing schemas.

``AuthRouteResult`` was originally defined in ``schemas.saml`` alongside the
SAML-only routing logic. As OIDC upstream IdPs became binding targets
(Iteration 6), the route result gained OIDC route types, so the schema moved
to this protocol-neutral home. ``schemas.saml`` re-exports it for backwards
compatibility.
"""

from pydantic import BaseModel, Field


class AuthRouteResult(BaseModel):
    """Result of authentication route determination.

    Every user is either:
    - Password user (saml_idp_id = NULL, no OIDC link) → route to password form
    - SAML IdP user (saml_idp_id = UUID) → route to that IdP
    - OIDC user (oidc_idp_user_links row) → route to that connection

    For unknown users:
    - If domain is bound to a SAML IdP with JIT → route to domain's IdP
    - If domain is bound to an OIDC connection with JIT → route to that connection
    - If default SAML IdP has JIT → route to default IdP
    - If default OIDC connection has JIT → route to default connection
    - Otherwise → not found
    """

    route_type: str = Field(
        ...,
        description=(
            "Route type: password, idp, idp_jit, idp_disabled, idp_oidc, "
            "idp_oidc_jit, idp_oidc_disabled, not_found, inactivated, "
            "no_auth_method, invalid_email"
        ),
    )
    idp_id: str | None = Field(
        None,
        description=(
            "IdP UUID if route_type is idp/idp_jit, or OIDC connection UUID if "
            "route_type is idp_oidc/idp_oidc_jit"
        ),
    )
    idp_name: str | None = Field(None, description="IdP name for display")
    user_id: str | None = Field(None, description="User UUID if user exists (internal use)")
