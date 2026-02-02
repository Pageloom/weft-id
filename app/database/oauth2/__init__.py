"""OAuth2 database operations.

This module provides all OAuth2-related database operations including:
- Client management (normal and B2B clients)
- Authorization code flow
- Token operations (access/refresh tokens)
"""

from database.oauth2.authorization import (
    cleanup_expired_codes,
    create_authorization_code,
    validate_and_consume_code,
)
from database.oauth2.clients import (
    create_b2b_client,
    create_normal_client,
    deactivate_client,
    delete_client,
    get_all_clients,
    get_b2b_client_by_service_user,
    get_client_by_client_id,
    get_client_by_id,
    reactivate_client,
    regenerate_client_secret,
    update_b2b_client_role,
    update_client,
)
from database.oauth2.tokens import (
    cleanup_expired_tokens,
    create_access_token,
    create_refresh_token,
    revoke_all_client_tokens,
    revoke_all_user_tokens,
    revoke_token,
    validate_refresh_token,
    validate_token,
)

__all__ = [
    # clients
    "create_normal_client",
    "create_b2b_client",
    "get_client_by_client_id",
    "get_client_by_id",
    "get_all_clients",
    "delete_client",
    "regenerate_client_secret",
    "get_b2b_client_by_service_user",
    "update_client",
    "update_b2b_client_role",
    "deactivate_client",
    "reactivate_client",
    # authorization
    "create_authorization_code",
    "validate_and_consume_code",
    "cleanup_expired_codes",
    # tokens
    "create_access_token",
    "create_refresh_token",
    "validate_token",
    "validate_refresh_token",
    "revoke_token",
    "revoke_all_client_tokens",
    "cleanup_expired_tokens",
    "revoke_all_user_tokens",
]
