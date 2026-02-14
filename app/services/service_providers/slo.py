"""Single Logout (SLO) processing for the IdP side.

SP-Initiated: Handles incoming LogoutRequests from downstream SPs.
IdP-Initiated: Propagates logout to all downstream SPs with active sessions.
"""

import logging

import database
import httpx
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import NotFoundError, ValidationError

logger = logging.getLogger(__name__)


def process_sp_logout_request(
    tenant_id: str,
    parsed_request: dict,
    base_url: str,
) -> tuple[str, str]:
    """Process a LogoutRequest from a downstream SP.

    Validates the issuer is a registered, enabled SP. Resolves the signing
    certificate and builds a signed LogoutResponse.

    Args:
        tenant_id: Tenant ID
        parsed_request: Dict from parse_sp_logout_request() with id, issuer, etc.
        base_url: Base URL for building the IdP entity ID

    Returns:
        Tuple of (base64_logout_response, sp_slo_url)

    Raises:
        NotFoundError: If SP not found or has no SLO URL
        ValidationError: If request is invalid (missing issuer)
    """
    from utils.saml import decrypt_private_key
    from utils.saml_slo import build_idp_logout_response

    issuer = parsed_request.get("issuer")
    if not issuer:
        raise ValidationError(
            message="LogoutRequest missing Issuer",
            code="slo_missing_issuer",
        )

    # Look up SP by entity ID
    sp_row = database.service_providers.get_service_provider_by_entity_id(tenant_id, issuer)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    if not sp_row.get("enabled", True):
        raise ValidationError(
            message="Service provider is disabled",
            code="sp_disabled",
        )

    slo_url = sp_row.get("slo_url")
    if not slo_url:
        raise NotFoundError(
            message="Service provider has no SLO URL configured",
            code="sp_no_slo_url",
        )

    # Resolve signing certificate (per-SP first, then tenant fallback)
    sp_id = str(sp_row["id"])
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        cert = database.saml.get_sp_certificate(tenant_id)
    if cert is None:
        raise NotFoundError(
            message="IdP signing certificate not configured",
            code="idp_certificate_not_found",
        )

    private_key_pem = decrypt_private_key(cert["private_key_pem_enc"])

    # Build the entity ID for this SP's metadata endpoint
    issuer_entity_id = f"{base_url}/saml/idp/metadata/{sp_id}"

    # Build signed LogoutResponse
    logout_response_b64 = build_idp_logout_response(
        issuer_entity_id=issuer_entity_id,
        destination=slo_url,
        in_response_to=parsed_request["id"],
        certificate_pem=cert["certificate_pem"],
        private_key_pem=private_key_pem,
    )

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="slo_sp_initiated",
        metadata={
            "sp_entity_id": issuer,
            "sp_name": sp_row["name"],
            "name_id": parsed_request.get("name_id"),
        },
    )

    return logout_response_b64, slo_url


def propagate_logout_to_sps(
    tenant_id: str,
    user_id: str,
    active_sps: list[dict],
    base_url: str,
) -> int:
    """Propagate logout to all downstream SPs with active sessions.

    For each SP that has an SLO URL, builds a signed LogoutRequest and
    POSTs it to the SP. Best-effort with short timeouts. Errors are
    logged but never block the caller.

    Args:
        tenant_id: Tenant ID
        user_id: The user being logged out
        active_sps: List of dicts with sp_id, sp_entity_id, name_id, session_index
        base_url: Base URL for building the IdP entity ID

    Returns:
        Number of SPs successfully notified
    """
    from utils.saml import decrypt_private_key
    from utils.saml_slo import build_idp_logout_request

    if not active_sps:
        return 0

    notified = 0

    for sp_info in active_sps:
        sp_id = sp_info.get("sp_id", "")
        sp_entity_id = sp_info.get("sp_entity_id", "")
        name_id = sp_info.get("name_id", "")
        session_index = sp_info.get("session_index")

        try:
            # Look up SP to get SLO URL
            sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
            if sp_row is None:
                logger.debug("SP %s not found, skipping SLO propagation", sp_id)
                continue

            slo_url = sp_row.get("slo_url")
            if not slo_url:
                logger.debug("SP %s has no SLO URL, skipping", sp_id)
                continue

            # Resolve signing certificate (per-SP first, then tenant fallback)
            cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
            if cert is None:
                cert = database.saml.get_sp_certificate(tenant_id)
            if cert is None:
                logger.warning("No signing certificate for SP %s, skipping SLO", sp_id)
                continue

            private_key_pem = decrypt_private_key(cert["private_key_pem_enc"])
            issuer_entity_id = f"{base_url}/saml/idp/metadata/{sp_id}"

            # Build signed LogoutRequest
            logout_request_b64 = build_idp_logout_request(
                issuer_entity_id=issuer_entity_id,
                destination=slo_url,
                name_id=name_id,
                name_id_format=None,
                session_index=session_index,
                certificate_pem=cert["certificate_pem"],
                private_key_pem=private_key_pem,
            )

            # POST the LogoutRequest to the SP (best-effort, short timeout)
            response = httpx.post(
                slo_url,
                data={"SAMLRequest": logout_request_b64},
                timeout=5.0,
            )
            if response.is_success:
                notified += 1
                logger.info("SLO propagated to SP %s (%s)", sp_id, sp_entity_id)
            else:
                logger.warning("SLO propagation to SP %s returned %s", sp_id, response.status_code)

        except Exception:
            logger.warning("SLO propagation failed for SP %s", sp_id, exc_info=True)

    # Log the propagation event
    if active_sps:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="slo_idp_propagated",
            metadata={
                "sp_count": len(active_sps),
                "notified_count": notified,
                "sp_entity_ids": [sp.get("sp_entity_id", "") for sp in active_sps],
            },
        )

    return notified
