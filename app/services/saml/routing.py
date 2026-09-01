"""Authentication routing logic (backwards-compatibility shim).

``determine_auth_route`` moved to the protocol-neutral
``services.auth_routing`` home in Iteration 6 because it now resolves OIDC
route types in addition to SAML. This module re-exports it so existing call
sites and tests that import ``services.saml.routing.determine_auth_route``
continue to work.
"""

from services.auth_routing import determine_auth_route  # noqa: F401

__all__ = ["determine_auth_route"]
