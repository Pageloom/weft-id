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

from services.oidc_upstream.adapters import (
    ClientCredentials,
    ProviderAdapter,
    ProviderCheckError,
    ProviderLoginError,
    SpecOIDCAdapter,
    UpstreamIdentity,
    callback_url,
    get_adapter,
    resolve_client_credentials,
)
from services.oidc_upstream.attributes import (
    apply_oidc_idp_attributes,
    scrub_oidc_canonical_matches_mirror,
)
from services.oidc_upstream.auth import (
    build_authorize_url,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
)
from services.oidc_upstream.connections import (
    POST_LOGOUT_PATH,
    create_connection,
    decrypt_client_secret,
    delete_connection,
    get_claim_mapping,
    get_connection,
    get_connection_row,
    list_connections,
    list_login_buttons,
    oidc_connection_requires_platform_mfa,
    set_connection_default,
    set_connection_enabled,
    test_connection,
    update_claim_mapping,
    update_connection,
)
from services.oidc_upstream.discovery import refresh_for_login, run_discovery
from services.oidc_upstream.domains import (
    bind_domain_to_connection,
    get_unbound_domains,
    list_domain_bindings,
    rebind_domain_to_connection,
    unbind_domain_from_connection,
)
from services.oidc_upstream.email_confirmation import (
    confirm_sign_in_email,
    pending_email_confirmation,
    requires_confirmed_email,
)
from services.oidc_upstream.errors import (
    DiscoveryError,
    DiscoveryInsecureEndpointError,
    DiscoveryIssuerMismatchError,
    DiscoveryRedirectError,
    DiscoveryUnavailableError,
    IDTokenAudienceError,
    IDTokenExpiredError,
    IDTokenIssuerError,
    IDTokenMissingClaimsError,
    IDTokenNonceError,
    IDTokenNotYetValidError,
    IDTokenSignatureError,
    IDTokenValidationError,
    JwksError,
    LogoutTokenError,
    OIDCUpstreamError,
)
from services.oidc_upstream.groups import (
    extract_group_names,
    has_group_claim_overage,
    sync_groups_from_claims,
)
from services.oidc_upstream.id_token import validate_id_token
from services.oidc_upstream.jwks import (
    clear_jwks_cache,
    get_jwks,
    refresh_jwks,
)
from services.oidc_upstream.links import (
    list_connection_linked_users,
    list_user_links,
    unlink_user_from_connection,
)
from services.oidc_upstream.login_state import (
    LoginState,
    attach_callback_fields,
    load_login_state,
    save_login_state,
    take_login_state,
)
from services.oidc_upstream.logout import (
    BackchannelLogoutResult,
    build_upstream_logout_url,
    handle_backchannel_logout,
    record_upstream_session,
    validate_logout_token,
)
from services.oidc_upstream.presets import (
    compose_entra_authority,
    compose_entra_discovery_url,
    email_linking_trusted,
    get_preset,
    get_preset_defaults,
    provider_display_name,
)
from services.oidc_upstream.provisioning import (
    ENTRY_LOGIN_BUTTON,
    ENTRY_ROUTED,
    authenticate_via_oidc,
    jit_provision_user,
)
from services.oidc_upstream.token_exchange import (
    TokenExchangeError,
    UserinfoError,
    UserinfoSubjectMismatchError,
    exchange_code,
    fetch_userinfo,
)

__all__ = [
    "LoginState",
    "attach_callback_fields",
    "load_login_state",
    "save_login_state",
    "take_login_state",
    "confirm_sign_in_email",
    "pending_email_confirmation",
    "requires_confirmed_email",
    "ClientCredentials",
    "ProviderAdapter",
    "ProviderCheckError",
    "ProviderLoginError",
    "SpecOIDCAdapter",
    "UpstreamIdentity",
    "callback_url",
    "get_adapter",
    "resolve_client_credentials",
    "provider_display_name",
    "email_linking_trusted",
    "list_connections",
    "get_connection",
    "get_connection_row",
    "list_login_buttons",
    "create_connection",
    "update_connection",
    "get_claim_mapping",
    "update_claim_mapping",
    "delete_connection",
    "set_connection_enabled",
    "set_connection_default",
    "test_connection",
    "oidc_connection_requires_platform_mfa",
    "decrypt_client_secret",
    "generate_pkce_pair",
    "generate_state",
    "generate_nonce",
    "build_authorize_url",
    "ENTRY_LOGIN_BUTTON",
    "ENTRY_ROUTED",
    "authenticate_via_oidc",
    "jit_provision_user",
    "extract_group_names",
    "has_group_claim_overage",
    "sync_groups_from_claims",
    "unlink_user_from_connection",
    "list_connection_linked_users",
    "list_user_links",
    "apply_oidc_idp_attributes",
    "scrub_oidc_canonical_matches_mirror",
    "list_domain_bindings",
    "bind_domain_to_connection",
    "unbind_domain_from_connection",
    "rebind_domain_to_connection",
    "get_unbound_domains",
    "run_discovery",
    "refresh_for_login",
    "validate_id_token",
    "validate_logout_token",
    "handle_backchannel_logout",
    "record_upstream_session",
    "build_upstream_logout_url",
    "POST_LOGOUT_PATH",
    "BackchannelLogoutResult",
    "LogoutTokenError",
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
    "UserinfoSubjectMismatchError",
    "OIDCUpstreamError",
    "DiscoveryError",
    "DiscoveryIssuerMismatchError",
    "DiscoveryInsecureEndpointError",
    "DiscoveryRedirectError",
    "DiscoveryUnavailableError",
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
