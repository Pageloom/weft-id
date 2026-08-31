"""OIDC upstream (relying-party) service layer.

Business logic for managing upstream OIDC IdP connections, mirroring the
SAML IdP service surface in ``services.saml.providers``. The client secret is
encrypted at rest (reversible) via the Fernet helper and never returned from
any read path.

All functions follow the service layer pattern:
- Receive RequestingUser for authorization
- Return Pydantic schemas
- Raise ServiceError subclasses on failure
- Log events for all writes
"""

from services.oidc_upstream.connections import (
    create_connection,
    delete_connection,
    get_connection,
    list_connections,
    oidc_connection_requires_platform_mfa,
    set_connection_default,
    set_connection_enabled,
    update_connection,
)

__all__ = [
    "list_connections",
    "get_connection",
    "create_connection",
    "update_connection",
    "delete_connection",
    "set_connection_enabled",
    "set_connection_default",
    "oidc_connection_requires_platform_mfa",
]
