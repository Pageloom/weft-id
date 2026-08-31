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


@dataclass(frozen=True)
class OIDCPreset:
    """Defaults for a provider preset.

    Attributes:
        provider_type: One of ``generic``, ``google``, ``entra``.
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
    """

    provider_type: str
    issuer: str | None
    discovery_url: str | None
    scopes: str
    correlation_claim: str
    requires_entra_tenant_id: bool = False


_PRESETS: dict[str, OIDCPreset] = {
    "generic": OIDCPreset(
        provider_type="generic",
        issuer=None,
        discovery_url=None,
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
    ),
    "google": OIDCPreset(
        provider_type="google",
        issuer="https://accounts.google.com",
        discovery_url="https://accounts.google.com/.well-known/openid-configuration",
        scopes=_DEFAULT_SCOPES,
        correlation_claim="sub",
    ),
    "entra": OIDCPreset(
        provider_type="entra",
        issuer=None,
        discovery_url=None,
        scopes=_ENTRA_SCOPES,
        correlation_claim="oid",
        requires_entra_tenant_id=True,
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
        "issuer": preset.issuer,
        "discovery_url": preset.discovery_url,
        "scopes": preset.scopes,
        "correlation_claim": preset.correlation_claim,
        "requires_entra_tenant_id": preset.requires_entra_tenant_id,
    }


def compose_entra_authority(entra_tenant_id: str) -> str:
    """Compose the Entra v2.0 authority URL from a tenant id.

    The tenant id may be a GUID, a verified domain, or one of the special
    values ``common`` / ``organizations`` / ``consumers``.
    """
    return _ENTRA_AUTHORITY_TEMPLATE.format(tenant_id=entra_tenant_id)


def compose_entra_discovery_url(entra_tenant_id: str) -> str:
    """Compose the Entra discovery document URL from a tenant id."""
    return f"{compose_entra_authority(entra_tenant_id)}/.well-known/openid-configuration"
