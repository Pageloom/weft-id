"""OIDC provider service layer.

Iteration 1 provides per-tenant signing-key management and JWKS assembly.
Iteration 2 adds scope-gated claim assembly and RS256 ID-token minting. Later
iterations add the userinfo endpoint, group claims, and client management.

Functions follow the service-layer pattern: authorization lives here, writes
emit event logs, and private key material never leaves this layer.
"""

from services.oidc.access import user_can_access_client
from services.oidc.claims import (
    SCOPE_DESCRIPTIONS,
    build_claims,
    parse_scope,
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
from services.oidc.tokens import ID_TOKEN_EXPIRY, issue_id_token, verify_id_token_hint
from services.oidc.userinfo import get_userinfo

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
    "ID_TOKEN_EXPIRY",
    "build_discovery_metadata",
    "get_userinfo",
]
