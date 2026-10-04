"""OIDC upstream provider presets.

Each preset supplies the defaults an admin can override when creating a
connection: the discovery/authority URL, the default scopes, and the
``correlation_claim`` used to correlate users. There are no forked code
paths -- the generic connector reads these values from the connection row,
so a preset is purely a set of defaults.

- **Generic** is the spec-correct default: no discovery URL (the admin
  supplies the issuer and either a discovery URL or manual endpoints), the
  standard ``openid profile email`` scopes, and ``sub`` correlation.
- **Google** points at ``https://accounts.google.com`` with the same scopes
  and ``sub`` correlation.
- **Entra** composes its authority from the tenant id
  (``https://login.microsoftonline.com/<entra_tenant_id>/v2.0``), requests
  ``openid profile email User.Read``, and correlates on ``oid`` (Entra's
  ``sub`` is per-app-anonymous; Microsoft guidance is to use ``oid``).
"""

from __future__ import annotations

from dataclasses import dataclass

# Standard scopes every preset requests. ``openid`` gates ID-token issuance,
# ``profile``/``email`` release the claims JIT provisioning needs.
_DEFAULT_SCOPES = "openid profile email"

# Entra additionally requests User.Read so the userinfo endpoint can return
# profile data (the Microsoft Graph permission for the delegated user).
_ENTRA_SCOPES = "openid profile email User.Read"

# Entra's v2.0 authority template. The tenant id is interpolated by the
# preset; "common"/"organizations"/"consumers" are also valid tenant ids.
_ENTRA_AUTHORITY_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/v2.0"

# The issuer Microsoft publishes for the ``consumers`` authority: the fixed id
# of the tenant that holds all personal Microsoft accounts.
_MICROSOFT_CONSUMERS_ISSUER = (
    "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
)

# How the client authenticates at the token endpoint (RFC 6749 2.3.1).
TOKEN_AUTH_BASIC = "client_secret_basic"
TOKEN_AUTH_POST = "client_secret_post"


@dataclass(frozen=True)
class OIDCPreset:
    """Defaults for a provider preset.

    Attributes:
        provider_type: The ``provider_type`` value stored on the connection.
        display_name: The provider's name as shown to admins.
        issuer: The issuer/authority URL, or None when the admin must supply
            one (generic) or when it is composed from another field (entra).
        discovery_url: The discovery document URL, or None when the admin
            must supply one (generic) or when it is composed from another
            field (entra).
        scopes: Default space-separated scope string.
        correlation_claim: The claim used to correlate users (``sub`` or
            ``oid``).
        requires_entra_tenant_id: Whether the preset needs an
            ``entra_tenant_id`` to compose its authority.
        token_auth_method: How the client secret is sent to the token
            endpoint: ``client_secret_basic`` (HTTP Basic, the default) or
            ``client_secret_post`` (form body).
        issuer_overridable: Whether an admin may replace the preset issuer
            with their own (a self-managed GitLab). The discovery URL then
            follows the issuer instead of the preset.
        email_linking_trusted: Whether the provider's ``email_verified``
            claim is reliable enough to attach a sign-in to an existing
            account by email. False for providers that assert no verified
            flag, or one that does not prove the user controls the address;
            such connections never email-link.
        login_label: The name on the sign-in page button ("Continue with
            <login_label>"), or None to use the connection's own name.
        logo: The brand logo file (``templates/provider_logos/<logo>.svg``)
            shown on the button, or None for no logo.
    """

    provider_type: str
    display_name: str
    issuer: str | None
    discovery_url: str | None
    scopes: str
    correlation_claim: str
    requires_entra_tenant_id: bool = False
    token_auth_method: str = TOKEN_AUTH_BASIC
    issuer_overridable: bool = False
    email_linking_trusted: bool = True
    login_label: str | None = None
    logo: str | None = None


_PRESETS: dict[str, OIDCPreset] = {
    "generic": OIDCPreset(
        provider_type="generic",
        display_name="Generic OIDC",
        issuer=None,
        discovery_url=None,
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
    ),
    "google": OIDCPreset(
        provider_type="google",
        display_name="Google",
        issuer="https://accounts.google.com",
        discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
        login_label="Google",
        logo="google",
    ),
    "entra": OIDCPreset(
        provider_type="entra",
        display_name="Entra ID",
        issuer=None,
        discovery_url=None,
        scopes=_ENTRA_SCOPES,
        correlation_claim="oid",
        requires_entra_tenant_id=True,
        login_label="Microsoft",
        logo="microsoft",
    ),
    "microsoft": OIDCPreset(
        provider_type="microsoft",
        display_name="Microsoft (personal accounts)",
        issuer=_MICROSOFT_CONSUMERS_ISSUER,
        discovery_url=(
            "https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration"
        ),
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
        # Personal Microsoft accounts carry no email_verified claim, and the
        # account's email need not be one the user controls.
        email_linking_trusted=False,
        login_label="Microsoft",
        logo="microsoft",
    ),
    "linkedin": OIDCPreset(
        provider_type="linkedin",
        display_name="LinkedIn",
        issuer="https://www.linkedin.com/oauth",
        discovery_url="https://www.linkedin.com/oauth/.well-known/openid-configuration",
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
        token_auth_method=TOKEN_AUTH_POST,
        login_label="LinkedIn",
        logo="linkedin",
    ),
    "gitlab": OIDCPreset(
        provider_type="gitlab",
        display_name="GitLab",
        issuer="https://gitlab.com",
        discovery_url="https://gitlab.com/.well-known/openid-configuration",
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
        issuer_overridable=True,
        login_label="GitLab",
        logo="gitlab",
    ),
}


def get_preset(provider_type: str) -> OIDCPreset | None:
    """Return the preset for a provider type, or None if unrecognized."""
    return _PRESETS.get(provider_type)


def get_preset_defaults(provider_type: str) -> dict:
    """Return the preset's defaults as a plain dict for form pre-filling.

    Returns an empty dict for an unrecognized provider type so callers can
    treat "no preset" and "unknown preset" uniformly.
    """
    preset = get_preset(provider_type)
    if preset is None:
        return {}
    return {
        "provider_type": preset.provider_type,
        "display_name": preset.display_name,
        "issuer": preset.issuer,
        "discovery_url": preset.discovery_url,
        "scopes": preset.scopes,
        "correlation_claim": preset.correlation_claim,
        "requires_entra_tenant_id": preset.requires_entra_tenant_id,
        "issuer_overridable": preset.issuer_overridable,
        "email_linking_trusted": preset.email_linking_trusted,
    }


def provider_display_name(provider_type: str) -> str:
    """Return the admin-facing name for a provider type.

    Falls back to the raw value for a type with no preset, so a row written
    by a newer release still renders.
    """
    preset = get_preset(provider_type)
    return preset.display_name if preset else provider_type


def login_button_style(provider_type: str) -> tuple[str | None, str | None]:
    """Return the sign-in button's ``(label, logo)`` for a provider type.

    Either may be None: no label means "use the connection name", no logo
    means a text-only button. A type with no preset gets neither.
    """
    preset = get_preset(provider_type)
    if preset is None:
        return None, None
    return preset.login_label, preset.logo


def token_auth_method(provider_type: str) -> str:
    """Return how a provider type sends the client secret to the token endpoint."""
    preset = get_preset(provider_type)
    return preset.token_auth_method if preset else TOKEN_AUTH_BASIC


def email_linking_trusted(provider_type: str) -> bool:
    """Return whether a provider type may link sign-ins to accounts by email.

    A type with no preset fails closed (False).
    """
    preset = get_preset(provider_type)
    return preset.email_linking_trusted if preset else False


def compose_entra_authority(entra_tenant_id: str) -> str:
    """Compose the Entra v2.0 authority URL from a tenant id.

    The tenant id may be a GUID, a verified domain, or one of the special
    values ``common`` / ``organizations`` / ``consumers``.
    """
    return _ENTRA_AUTHORITY_TEMPLATE.format(tenant_id=entra_tenant_id)


def compose_entra_discovery_url(entra_tenant_id: str) -> str:
    """Compose the Entra discovery document URL from a tenant id."""
    return f"{compose_entra_authority(entra_tenant_id)}/.well-known/openid-configuration"
