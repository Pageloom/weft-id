"""Inbound SCIM 2.0 endpoint family.

This package houses the routes upstream IdPs (Okta, Entra) call to
provision and read directory state in WeftID. The current submodule
is `inbound/` (servicing IdP → WeftID flows); outbound SCIM lives
elsewhere in `app/services/scim/` because we are the client there,
not the server.

URL prefix: `/scim/v2/inbound/{idp_id}/`. The `{idp_id}` segment is
the `saml_identity_providers.id` the bearer token is bound to.
"""

from .inbound import router

__all__ = ["router"]
