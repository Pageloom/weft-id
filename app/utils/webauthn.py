"""WebAuthn (passkey) utilities.

Thin wrapper around the ``webauthn`` (py_webauthn) library so the service layer
stays framework-agnostic. This module exposes:

- ``rp_id_for_tenant`` / ``origin_for_tenant`` -- derive RP ID and origin from
  the tenant record (not from request headers).
- ``rp_name_for_tenant`` -- resolves the tenant display name for the RP name.
- ``generate_registration_options_for_user`` -- build a
  ``PublicKeyCredentialCreationOptions`` JSON dict and the raw challenge.
- ``verify_registration`` -- verify a registration response from the browser.
- ``WebAuthnError`` -- raised on any verification failure.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import Request
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import exceptions as webauthn_exc
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration


class WebAuthnError(Exception):
    """Raised when a WebAuthn ceremony fails (invalid signature, bad challenge, etc.)."""


class SignCountRegressionError(WebAuthnError):
    """Raised when the authenticator's sign count regressed, indicating a cloned credential."""


def _tenant_host(tenant_id: str) -> str:
    """Return ``subdomain.BASE_DOMAIN`` for the tenant, derived from the DB.

    Falls back to BASE_DOMAIN alone if the tenant is not found (defensive).
    """
    import database

    tenant = database.tenants.get_tenant_by_id(tenant_id)
    subdomain = tenant["subdomain"] if tenant else None
    base = _base_domain()
    if subdomain and base:
        return f"{subdomain}.{base}"
    return base or "localhost"


def _base_domain() -> str:
    import settings

    return settings.BASE_DOMAIN


def rp_id_for_tenant(tenant_id: str) -> str:
    """Return the Relying Party ID computed from the tenant record.

    The RP ID is the bare domain (no port, no scheme). Computed server-side
    from the tenant's subdomain and BASE_DOMAIN so it cannot be influenced
    by spoofed request headers.
    """
    return _tenant_host(tenant_id)


def rp_name_for_tenant(tenant_id: str) -> str:
    """Return the human-readable tenant name for the Relying Party name."""
    import database

    tenant = database.tenants.get_tenant_by_id(tenant_id)
    if tenant:
        return str(tenant.get("name") or tenant.get("subdomain") or "WeftID")
    return "WeftID"


def origin_for_tenant(tenant_id: str, request: Request) -> str:
    """Return the expected WebAuthn origin for the tenant.

    The host portion is derived from the tenant record (not from request
    headers) so a spoofed X-Forwarded-Host cannot shift the origin. The
    scheme and optional port are taken from the reverse proxy headers
    because they reflect how the browser reached the site.
    """
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = _tenant_host(tenant_id)
    raw_header = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    port = ""
    if ":" in raw_header:
        port_str = raw_header.rsplit(":", 1)[1]
        if port_str.isdigit():
            p = int(port_str)
            if (scheme == "https" and p != 443) or (scheme == "http" and p != 80):
                port = f":{p}"
    return f"{scheme}://{host}{port}"


def generate_registration_options_for_user(
    rp_id: str,
    rp_name: str,
    user_id_bytes: bytes,
    user_name: str,
    user_display_name: str,
    existing_credential_ids: list[bytes],
) -> tuple[dict[str, Any], bytes]:
    """Build WebAuthn registration options for a user.

    Returns a tuple of (options_json_dict, challenge_bytes). The options dict
    is JSON-serializable and safe to return directly to the browser; the raw
    challenge bytes should be stashed server-side (session) for verification.
    """
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id_bytes,
        user_name=user_name,
        user_display_name=user_display_name,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=cid) for cid in existing_credential_ids
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    options_json_str = options_to_json(options)
    options_dict: dict[str, Any] = json.loads(options_json_str)
    return options_dict, options.challenge


def generate_authentication_options_for_user(
    rp_id: str,
    allowed_credential_ids: list[bytes],
) -> tuple[dict[str, Any], bytes]:
    """Build WebAuthn authentication options for a user.

    Returns a tuple of (options_json_dict, challenge_bytes). ``allow_credentials``
    scopes the ceremony to the user's registered credentials (not a
    discoverable pick-any). The raw challenge bytes should be stashed
    server-side (session) for verification.
    """
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cid) for cid in allowed_credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    options_json_str = options_to_json(options)
    options_dict: dict[str, Any] = json.loads(options_json_str)
    return options_dict, options.challenge


def verify_authentication(
    response: dict[str, Any],
    expected_challenge: bytes,
    expected_rp_id: str,
    expected_origin: str,
    credential_public_key: bytes,
    credential_current_sign_count: int,
    require_user_verification: bool = True,
) -> VerifiedAuthentication:
    """Verify a WebAuthn authentication assertion returned by the browser.

    Raises:
        WebAuthnError: on any verification failure (bad challenge, bad origin,
            invalid signature, sign-count regression, etc.).
    """
    try:
        return verify_authentication_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=credential_current_sign_count,
            require_user_verification=require_user_verification,
        )
    except webauthn_exc.InvalidAuthenticationResponse as exc:
        msg = str(exc).lower()
        if "sign count" in msg or "counter" in msg:
            raise SignCountRegressionError(str(exc)) from exc
        raise WebAuthnError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise WebAuthnError(f"Authentication verification failed: {exc}") from exc


def verify_registration(
    response: dict[str, Any],
    expected_challenge: bytes,
    expected_rp_id: str,
    expected_origin: str,
) -> VerifiedRegistration:
    """Verify a registration response returned by the browser.

    Raises:
        WebAuthnError: on any verification failure (bad challenge, bad origin,
            invalid signature, etc.).
    """
    try:
        return verify_registration_response(
            credential=response,
            expected_challenge=expected_challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            require_user_verification=True,
        )
    except webauthn_exc.InvalidRegistrationResponse as exc:
        raise WebAuthnError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise WebAuthnError(f"Registration verification failed: {exc}") from exc
