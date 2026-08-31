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

from services.oidc_upstream.auth import (
    build_authorize_url,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
)
from services.oidc_upstream.connections import (
    create_connection,
    decrypt_client_secret,
    delete_connection,
    get_connection,
    get_connection_row,
    list_connections,
    oidc_connection_requires_platform_mfa,
    set_connection_default,
    set_connection_enabled,
    update_connection,
)
from services.oidc_upstream.discovery import run_discovery
from services.oidc_upstream.errors import (
    DiscoveryError,
    DiscoveryInsecureEndpointError,
    DiscoveryIssuerMismatchError,
    DiscoveryRedirectError,
    IDTokenAudienceError,
    IDTokenExpiredError,
    IDTokenIssuerError,
    IDTokenMissingClaimsError,
    IDTokenNonceError,
    IDTokenNotYetValidError,
    IDTokenSignatureError,
    IDTokenValidationError,
    JwksError,
    OIDCUpstreamError,
)
from services.oidc_upstream.id_token import validate_id_token
from services.oidc_upstream.jwks import (
    clear_jwks_cache,
    get_jwks,
    refresh_jwks,
)
from services.oidc_upstream.presets import (
    compose_entra_authority,
    compose_entra_discovery_url,
    get_preset,
    get_preset_defaults,
)
from services.oidc_upstream.provisioning import (
    authenticate_via_oidc,
    jit_provision_user,
)
from services.oidc_upstream.token_exchange import (
    TokenExchangeError,
    UserinfoError,
    exchange_code,
    fetch_userinfo,
)

__all__ = [
    "list_connections",
    "get_connection",
    "get_connection_row",
    "create_connection",
    "update_connection",
    "delete_connection",
    "set_connection_enabled",
    "set_connection_default",
    "oidc_connection_requires_platform_mfa",
    "decrypt_client_secret",
    "generate_pkce_pair",
    "generate_state",
    "generate_nonce",
    "build_authorize_url",
    "authenticate_via_oidc",
    "jit_provision_user",
    "run_discovery",
    "validate_id_token",
    "get_jwks",
    "refresh_jwks",
    "clear_jwks_cache",
    "get_preset",
    "get_preset_defaults",
    "compose_entra_authority",
    "compose_entra_discovery_url",
    "exchange_code",
    "fetch_userinfo",
    "TokenExchangeError",
    "UserinfoError",
    "OIDCUpstreamError",
    "DiscoveryError",
    "DiscoveryIssuerMismatchError",
    "DiscoveryInsecureEndpointError",
    "DiscoveryRedirectError",
    "JwksError",
    "IDTokenValidationError",
    "IDTokenSignatureError",
    "IDTokenIssuerError",
    "IDTokenAudienceError",
    "IDTokenNonceError",
    "IDTokenExpiredError",
    "IDTokenNotYetValidError",
    "IDTokenMissingClaimsError",
]
