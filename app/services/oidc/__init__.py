"""OIDC provider service layer.

Iteration 1 provides per-tenant signing-key management and JWKS assembly.
Iteration 2 adds scope-gated claim assembly and RS256 ID-token minting. Later
iterations add the userinfo endpoint, group claims, and client management.

Functions follow the service-layer pattern: authorization lives here, writes
emit event logs, and private key material never leaves this layer.
"""

from services.oidc.access import user_can_access_client
from services.oidc.backchannel import (
    build_logout_token,
    cleanup_backchannel_logout_state,
    deliver_due_backchannel_logouts,
    list_backchannel_logout_deliveries,
    list_tenants_with_due_backchannel_logouts,
)
from services.oidc.claims import (
    SCOPE_DESCRIPTIONS,
    build_claims,
    parse_scope,
)
from services.oidc.consent import (
    consent_covers,
    get_granted_scopes,
    list_client_grants,
    list_my_grants,
    record_consent,
    revoke_client_grant,
    revoke_my_grant,
)
from services.oidc.discovery import build_discovery_metadata
from services.oidc.keys import (
    ActiveSigningKey,
    cleanup_previous_signing_key,
    force_cleanup_previous_signing_key,
    get_active_signing_key,
    get_jwks,
    get_signing_key_status,
    get_verification_public_keys,
    list_signing_keys_needing_cleanup,
    rotate_signing_key,
)
from services.oidc.logout import (
    EndSessionRequest,
    OidcSessionEnd,
    end_oidc_session,
    end_user_oidc_sessions,
    resolve_end_session_request,
)
from services.oidc.tokens import ID_TOKEN_EXPIRY, issue_id_token, verify_id_token_hint
from services.oidc.userinfo import (
    USERINFO_SIGNING_ALG_VALUES_SUPPORTED,
    get_userinfo,
    sign_userinfo,
)

__all__ = [
    "ActiveSigningKey",
    "get_active_signing_key",
    "get_jwks",
    "get_verification_public_keys",
    "rotate_signing_key",
    "get_signing_key_status",
    "cleanup_previous_signing_key",
    "force_cleanup_previous_signing_key",
    "list_signing_keys_needing_cleanup",
    "build_claims",
    "parse_scope",
    "SCOPE_DESCRIPTIONS",
    "user_can_access_client",
    "issue_id_token",
    "verify_id_token_hint",
    "EndSessionRequest",
    "resolve_end_session_request",
    "end_oidc_session",
    "end_user_oidc_sessions",
    "OidcSessionEnd",
    "build_logout_token",
    "deliver_due_backchannel_logouts",
    "list_backchannel_logout_deliveries",
    "list_tenants_with_due_backchannel_logouts",
    "cleanup_backchannel_logout_state",
    "ID_TOKEN_EXPIRY",
    "build_discovery_metadata",
    "get_userinfo",
    "sign_userinfo",
    "USERINFO_SIGNING_ALG_VALUES_SUPPORTED",
    "consent_covers",
    "get_granted_scopes",
    "record_consent",
    "list_my_grants",
    "revoke_my_grant",
    "list_client_grants",
    "revoke_client_grant",
]
