"""Single Logout (SLO) flows for SAML SSO (WeftID as the service provider).

SP-initiated: ``initiate_sp_logout`` builds the signed LogoutRequest that
sends the browser to the IdP when a WeftID session ends.

IdP-initiated: ``process_idp_logout_request`` validates a LogoutRequest the
IdP sent through the browser (front channel) and returns who it signs out plus
the signed LogoutResponse URL. The router ends the WeftID session when the
browser's session is the one named. A LogoutRequest sent server to server (no
browser, so no session cookie) is answered but ends nothing.
"""

import logging
from dataclasses import dataclass
from typing import Any

import database
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.saml.idp_certificates import get_certificates_for_validation
from utils.saml import (
    LogoutRequestError,
    build_logout_request,
    build_logout_response,
    build_saml_settings,
    decode_logout_request,
    decrypt_private_key,
    logout_request_issuer,
    make_sp_entity_id,
    validate_logout_request,
)

logger = logging.getLogger(__name__)

# The longest RelayState echoed back to the IdP (Bindings 3.4.3: 80 bytes is
# the SHOULD; anything much longer is not a RelayState an IdP would send).
_MAX_RELAY_STATE_LENGTH = 1024


@dataclass(frozen=True)
class IdpLogoutRequest:
    """A validated IdP-initiated LogoutRequest.

    Attributes:
        idp_id: The WeftID registration of the IdP that sent it.
        name_id: The NameID it signs out.
        session_indexes: The SessionIndex values it names (empty means every
            session of that NameID).
        response_url: The IdP's SLO URL carrying the signed LogoutResponse.
    """

    idp_id: str
    name_id: str
    session_indexes: list[str]
    response_url: str


def _sp_settings_for_idp(
    tenant_id: str, idp_id: str, idp: dict, base_url: str
) -> dict[str, Any] | None:
    """python3-saml settings for talking to ``idp`` (None without an SP certificate)."""
    # SP certificate: per-IdP first, then the tenant-level fallback.
    sp_cert = database.saml.get_idp_sp_certificate(tenant_id, idp_id)
    if not sp_cert:
        sp_cert = database.saml.get_sp_certificate(tenant_id)
    if not sp_cert:
        return None

    idp_certs = get_certificates_for_validation(tenant_id, idp_id)
    if not idp_certs:
        idp_certs = [idp["certificate_pem"]]

    return build_saml_settings(
        sp_entity_id=make_sp_entity_id(tenant_id, idp_id),
        sp_acs_url=idp["sp_entity_id"].replace("/saml/metadata", "/saml/acs"),
        sp_certificate_pem=sp_cert["certificate_pem"],
        sp_private_key_pem=decrypt_private_key(sp_cert["private_key_pem_enc"]),
        idp_entity_id=idp["entity_id"],
        idp_sso_url=idp["sso_url"],
        idp_certificate_pem=idp_certs[0],
        idp_slo_url=idp["slo_url"],
        sp_slo_url=f"{base_url}/saml/slo",
        idp_certificate_pems=idp_certs,
    )


def initiate_sp_logout(
    tenant_id: str,
    saml_idp_id: str,
    name_id: str,
    name_id_format: str | None,
    session_index: str | None,
    base_url: str,
) -> str | None:
    """
    Build SP-initiated logout request.

    No authorization required (called during logout flow).

    Returns redirect URL if IdP has SLO configured, None otherwise.
    SLO errors are logged but don't raise exceptions (non-blocking).

    Args:
        tenant_id: Tenant ID
        saml_idp_id: ID of the IdP the user logged in with
        name_id: NameID from the original SAML assertion
        name_id_format: NameID format (optional)
        session_index: Session index from the original assertion (optional)
        base_url: Base URL for building SP SLO URL

    Returns:
        Redirect URL for IdP SLO, or None if SLO not configured
    """
    try:
        idp = database.saml.get_identity_provider(tenant_id, saml_idp_id)
        if not idp or not idp.get("slo_url"):
            return None

        settings = _sp_settings_for_idp(tenant_id, saml_idp_id, idp, base_url)
        if settings is None:
            logger.warning(f"No SP certificate for tenant {tenant_id}, skipping SLO")
            return None

        redirect_url, _request_id = build_logout_request(
            settings=settings,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
        )

        logger.info(f"SLO initiated for tenant {tenant_id}, IdP {saml_idp_id}")
        return redirect_url

    except Exception as e:
        # SLO errors should never block logout
        logger.warning(f"SLO initiation failed for tenant {tenant_id}: {e}")
        return None


def process_idp_logout_request(
    tenant_id: str,
    saml_request: str,
    base_url: str,
    *,
    request_data: dict[str, Any],
    relay_state: str | None = None,
) -> IdpLogoutRequest | None:
    """Validate an IdP-initiated LogoutRequest and build the LogoutResponse.

    No authorization required (the IdP's signature is the authentication).

    The IdP is found by the request's ``Issuer`` and must have an SLO URL
    (where the response goes). The request must be signed by it and pass
    python3-saml's strict checks (``utils.saml.validate_logout_request``).

    Args:
        tenant_id: Tenant ID
        saml_request: The SAMLRequest parameter as received
        base_url: Base URL of the tenant (the SP SLO endpoint lives under it)
        request_data: python3-saml request data for this endpoint (see
            ``validate_logout_request``)
        relay_state: The request's RelayState, echoed in the response

    Returns:
        The validated request, or None when it was refused (logged, and
        audited as ``saml_idp_logout_rejected`` when the IdP is known).
    """
    try:
        issuer = logout_request_issuer(decode_logout_request(saml_request))
    except LogoutRequestError:
        issuer = None
    if not issuer:
        logger.warning("IdP-initiated SLO: could not determine the issuer")
        return None

    try:
        idp = database.saml.get_identity_provider_by_entity_id(tenant_id, issuer)
        if not idp or not idp.get("slo_url"):
            logger.warning("IdP-initiated SLO: no IdP with an SLO URL for issuer %s", issuer)
            return None

        idp_id = str(idp["id"])
        settings = _sp_settings_for_idp(tenant_id, idp_id, idp, base_url)
        if settings is None:
            logger.warning("IdP-initiated SLO: no SP certificate for tenant %s", tenant_id)
            return None
    except Exception:
        logger.warning("IdP-initiated SLO failed for tenant %s", tenant_id, exc_info=True)
        return None

    try:
        request_id, name_id, session_indexes = validate_logout_request(
            settings, saml_request, request_data=request_data
        )
    except LogoutRequestError as exc:
        logger.warning("IdP-initiated SLO from %s rejected: %s", issuer, exc)
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="saml_identity_provider",
            artifact_id=idp_id,
            event_type="saml_idp_logout_rejected",
            metadata={"idp_name": idp.get("name"), "reason": exc.reason},
        )
        return None

    if relay_state is not None and len(relay_state) > _MAX_RELAY_STATE_LENGTH:
        relay_state = None

    try:
        response_url = build_logout_response(
            settings, in_response_to=request_id, relay_state=relay_state
        )
    except Exception:
        logger.warning("IdP-initiated SLO: could not build the response", exc_info=True)
        return None

    return IdpLogoutRequest(
        idp_id=idp_id,
        name_id=name_id,
        session_indexes=session_indexes,
        response_url=response_url,
    )
