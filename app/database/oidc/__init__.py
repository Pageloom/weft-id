"""OIDC provider database operations.

Currently holds per-tenant signing-key queries (mirrors the shape of
sp_signing_certificates). Future iterations add authorization-code scope,
client, and token queries here.
"""

from database.oidc.claims import get_user_claim_data
from database.oidc.signing_keys import (
    clear_previous_signing_key,
    create_signing_key,
    get_signing_key,
    get_signing_keys_needing_cleanup,
    rotate_signing_key,
)

__all__ = [
    "get_signing_key",
    "create_signing_key",
    "rotate_signing_key",
    "clear_previous_signing_key",
    "get_signing_keys_needing_cleanup",
    "get_user_claim_data",
]
