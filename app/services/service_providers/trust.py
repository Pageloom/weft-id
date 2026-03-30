"""SP trust establishment operations.

Handles establishing trust between WeftID and downstream service providers,
via metadata URL, metadata XML, or manual entry.
"""

import database
from schemas.service_providers import SPConfig
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError, ValidationError
from services.service_providers._converters import _row_to_config
from services.types import RequestingUser


def _do_establish_trust(
    tenant_id: str,
    requesting_user: RequestingUser,
    sp_id: str,
    entity_id: str,
    acs_url: str,
    certificate_pem: str | None = None,
    encryption_certificate_pem: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    metadata_xml: str | None = None,
    metadata_url: str | None = None,
    slo_url: str | None = None,
    sp_requested_attributes: list[dict] | None = None,
    attribute_mapping: dict[str, str] | None = None,
    method: str = "manual",
) -> SPConfig:
    """Common logic for all trust establishment methods."""
    # Verify SP exists and trust is not already established
    existing = database.service_providers.get_service_provider(tenant_id, sp_id)
    if existing is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )
    if existing.get("trust_established", False):
        raise ValidationError(
            message="Trust has already been established with this service provider",
            code="sp_trust_already_established",
        )

    # Check for duplicate entity_id
    dup = database.service_providers.get_service_provider_by_entity_id(tenant_id, entity_id)
    if dup:
        raise ConflictError(
            message=f"A service provider with entity ID '{entity_id}' already exists",
            code="sp_entity_id_exists",
        )

    row = database.service_providers.establish_trust(
        tenant_id=tenant_id,
        sp_id=sp_id,
        entity_id=entity_id,
        acs_url=acs_url,
        certificate_pem=certificate_pem,
        encryption_certificate_pem=encryption_certificate_pem,
        nameid_format=nameid_format,
        metadata_xml=metadata_xml,
        metadata_url=metadata_url,
        slo_url=slo_url,
        sp_requested_attributes=sp_requested_attributes,
        attribute_mapping=attribute_mapping,
    )

    if row is None:
        raise ValidationError(
            message="Failed to establish trust (SP may have been updated concurrently)",
            code="sp_trust_establishment_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="service_provider_trust_established",
        metadata={
            "name": existing["name"],
            "entity_id": entity_id,
            "method": method,
        },
    )

    config = _row_to_config(row)
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]
    return config


def establish_trust_from_metadata_url(
    requesting_user: RequestingUser,
    sp_id: str,
    metadata_url: str,
) -> SPConfig:
    """Establish trust by fetching and parsing the SP's metadata URL.

    Authorization: Requires super_admin role.
    Logs: service_provider_trust_established event.
    """
    from utils.saml_idp import fetch_sp_metadata, parse_sp_metadata_xml

    require_super_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    try:
        metadata_xml = fetch_sp_metadata(metadata_url)
    except ValueError as e:
        raise ValidationError(message=str(e), code="sp_metadata_fetch_error")

    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(message=str(e), code="sp_metadata_parse_error")

    sp_requested_attributes = parsed.get("requested_attributes")
    attribute_mapping = None
    if sp_requested_attributes:
        from utils.saml_idp import auto_detect_attribute_mapping

        attribute_mapping = auto_detect_attribute_mapping(sp_requested_attributes) or None

    return _do_establish_trust(
        tenant_id=tenant_id,
        requesting_user=requesting_user,
        sp_id=sp_id,
        entity_id=parsed["entity_id"],
        acs_url=parsed["acs_url"],
        certificate_pem=parsed.get("certificate_pem"),
        encryption_certificate_pem=parsed.get("encryption_certificate_pem"),
        nameid_format=parsed.get(
            "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        metadata_xml=metadata_xml,
        metadata_url=metadata_url,
        slo_url=parsed.get("slo_url"),
        sp_requested_attributes=sp_requested_attributes,
        attribute_mapping=attribute_mapping,
        method="metadata_url",
    )


def establish_trust_from_metadata_xml(
    requesting_user: RequestingUser,
    sp_id: str,
    metadata_xml: str,
) -> SPConfig:
    """Establish trust by parsing provided SP metadata XML.

    Authorization: Requires super_admin role.
    Logs: service_provider_trust_established event.
    """
    from utils.saml_idp import parse_sp_metadata_xml

    require_super_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(message=str(e), code="sp_metadata_parse_error")

    sp_requested_attributes = parsed.get("requested_attributes")
    attribute_mapping = None
    if sp_requested_attributes:
        from utils.saml_idp import auto_detect_attribute_mapping

        attribute_mapping = auto_detect_attribute_mapping(sp_requested_attributes) or None

    return _do_establish_trust(
        tenant_id=tenant_id,
        requesting_user=requesting_user,
        sp_id=sp_id,
        entity_id=parsed["entity_id"],
        acs_url=parsed["acs_url"],
        certificate_pem=parsed.get("certificate_pem"),
        encryption_certificate_pem=parsed.get("encryption_certificate_pem"),
        nameid_format=parsed.get(
            "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        metadata_xml=metadata_xml,
        slo_url=parsed.get("slo_url"),
        sp_requested_attributes=sp_requested_attributes,
        attribute_mapping=attribute_mapping,
        method="metadata_xml",
    )


def establish_trust_manually(
    requesting_user: RequestingUser,
    sp_id: str,
    entity_id: str,
    acs_url: str,
    slo_url: str | None = None,
) -> SPConfig:
    """Establish trust by manually providing entity_id and acs_url.

    Authorization: Requires super_admin role.
    Logs: service_provider_trust_established event.
    """
    require_super_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    return _do_establish_trust(
        tenant_id=tenant_id,
        requesting_user=requesting_user,
        sp_id=sp_id,
        entity_id=entity_id,
        acs_url=acs_url,
        slo_url=slo_url,
        method="manual",
    )
