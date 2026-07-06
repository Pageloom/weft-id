"""OIDC provider service layer.

Iteration 1 provides per-tenant signing-key management and JWKS assembly.
Later iterations add ID-token minting, scope-gated claim assembly, and
client management.

Functions follow the service-layer pattern: authorization lives here, writes
emit event logs, and private key material never leaves this layer.
"""

from services.oidc.keys import (
    ActiveSigningKey,
    cleanup_previous_signing_key,
    get_active_signing_key,
    get_jwks,
    rotate_signing_key,
)

__all__ = [
    "ActiveSigningKey",
    "get_active_signing_key",
    "get_jwks",
    "rotate_signing_key",
    "cleanup_previous_signing_key",
]
