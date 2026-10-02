"""OAuth2 database operations.

This module provides all OAuth2-related database operations including:
- Client management (normal and B2B clients)
- Client assertion replay protection (private_key_jwt)
- Authorization code flow
- Device authorization grant (RFC 8628)
- Token operations (access/refresh tokens)
- Remembered consent grants
- Which clients received an ID token in which session (logout fan-out)
- Back-channel logout deliveries (queue and delivery log)
- Dynamic client registration (settings, initial access tokens, registered clients)
"""

from database.oauth2.assertions import record_client_assertion_jti
from database.oauth2.authorization import (
    cleanup_expired_codes,
    create_authorization_code,
    validate_and_consume_code,
)
from database.oauth2.backchannel import (
    claim_due_deliveries,
    count_client_deliveries_by_status,
    list_client_deliveries,
    list_tenants_with_due_deliveries,
    mark_delivered,
    mark_failed,
    mark_retry,
    purge_finished_deliveries,
    sweep_stale_session_clients,
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
    set_client_authentication,
    set_client_subject_type,
    set_client_tenant_introspection,
    update_b2b_client_role,
    update_client,
    update_client_oidc_settings,
)
from database.oauth2.consent import (
    delete_consent_grant,
    delete_consent_grants_for_client,
    delete_consent_grants_for_user,
    get_consent_grant,
    get_consent_grant_by_id,
    list_consent_grants_for_client,
    list_consent_grants_for_user,
    upsert_consent_grant,
)
from database.oauth2.device import (
    cleanup_expired_device_codes,
    create_device_code,
    decide_device_code,
    find_device_code,
    get_pending_by_user_code,
    record_poll,
    redeem_device_code,
)
from database.oauth2.pushed import consume_pushed_request, create_pushed_request
from database.oauth2.registration import (
    create_initial_access_token,
    create_registered_client,
    get_initial_access_token,
    get_initial_access_token_by_hash,
    get_registration_settings,
    list_initial_access_tokens,
    replace_registered_client,
    revoke_initial_access_token,
    touch_initial_access_token,
    upsert_registration_settings,
)
from database.oauth2.sessions import (
    consume_session_clients,
    consume_user_session_clients,
    upsert_session_client,
)
from database.oauth2.tokens import (
    create_access_token,
    create_refresh_token,
    delete_token,
    find_token,
    purge_expired_tokens,
    revoke_all_client_tokens,
    revoke_all_user_tokens,
    revoke_grant_tokens,
    revoke_session_refresh_tokens,
    revoke_token,
    rotate_refresh_token,
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
    "update_client_oidc_settings",
    "set_client_tenant_introspection",
    "set_client_authentication",
    "set_client_subject_type",
    "update_b2b_client_role",
    "deactivate_client",
    "reactivate_client",
    # client assertions
    "record_client_assertion_jti",
    # pushed authorization requests
    "create_pushed_request",
    "consume_pushed_request",
    # authorization
    "create_authorization_code",
    "validate_and_consume_code",
    "cleanup_expired_codes",
    # device authorization grant
    "create_device_code",
    "get_pending_by_user_code",
    "decide_device_code",
    "find_device_code",
    "record_poll",
    "redeem_device_code",
    "cleanup_expired_device_codes",
    # tokens
    "create_access_token",
    "create_refresh_token",
    "validate_token",
    "validate_refresh_token",
    "find_token",
    "delete_token",
    "revoke_token",
    "revoke_all_client_tokens",
    "purge_expired_tokens",
    "revoke_all_user_tokens",
    "revoke_grant_tokens",
    "revoke_session_refresh_tokens",
    "rotate_refresh_token",
    # consent
    "get_consent_grant",
    "get_consent_grant_by_id",
    "upsert_consent_grant",
    "list_consent_grants_for_user",
    "list_consent_grants_for_client",
    "delete_consent_grant",
    "delete_consent_grants_for_user",
    "delete_consent_grants_for_client",
    # dynamic client registration
    "get_registration_settings",
    "upsert_registration_settings",
    "create_initial_access_token",
    "list_initial_access_tokens",
    "get_initial_access_token",
    "get_initial_access_token_by_hash",
    "revoke_initial_access_token",
    "touch_initial_access_token",
    "create_registered_client",
    "replace_registered_client",
    # sessions
    "upsert_session_client",
    "consume_session_clients",
    "consume_user_session_clients",
    # back-channel logout deliveries
    "list_tenants_with_due_deliveries",
    "claim_due_deliveries",
    "count_client_deliveries_by_status",
    "list_client_deliveries",
    "mark_delivered",
    "mark_retry",
    "mark_failed",
    "purge_finished_deliveries",
    "sweep_stale_session_clients",
]
