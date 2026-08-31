"""OIDC upstream (relying-party) database operations.

Mirrors the shape of ``database.saml`` for the consuming direction of OIDC:
connection CRUD plus the user-link table that maps an upstream ``sub`` claim
to a WeftID user. Every query is RLS-scoped via the ``tenant_id`` argument to
the database helpers, so only the calling tenant's rows are ever visible.
"""

from database.oidc_upstream.attributes import (
    delete_for_user,
    delete_for_user_idp,
    list_attributes,
    list_attributes_for_idp,
    replace_idp_attributes,
)
from database.oidc_upstream.connections import (
    create_connection,
    delete_connection,
    get_connection,
    get_connection_by_issuer,
    get_default_connection,
    get_enabled_connections,
    list_connections,
    set_connection_default,
    set_connection_enabled,
    update_connection,
)
from database.oidc_upstream.links import (
    count_links_for_connection,
    create_link,
    delete_link,
    get_link,
    get_link_by_idp_sub,
    get_user_id_by_sub,
)

__all__ = [
    # connections
    "list_connections",
    "get_connection",
    "get_connection_by_issuer",
    "create_connection",
    "update_connection",
    "set_connection_enabled",
    "set_connection_default",
    "delete_connection",
    "get_enabled_connections",
    "get_default_connection",
    # links
    "create_link",
    "get_link",
    "get_link_by_idp_sub",
    "get_user_id_by_sub",
    "delete_link",
    "count_links_for_connection",
    # attributes
    "list_attributes",
    "list_attributes_for_idp",
    "replace_idp_attributes",
    "delete_for_user",
    "delete_for_user_idp",
]
