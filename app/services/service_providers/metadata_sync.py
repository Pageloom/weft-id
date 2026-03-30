"""SP metadata lifecycle operations.

Handles previewing and applying metadata refreshes (from stored URL) and
reimports (from supplied XML) for downstream service providers.
"""

import hashlib
import json

import database
from schemas.service_providers import SPConfig, SPMetadataChangePreview, SPMetadataFieldChange
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.service_providers._converters import _row_to_config
from services.types import RequestingUser


def _cert_fingerprint(pem: str | None) -> str | None:
    """Compute SHA-256 fingerprint of a PEM certificate for display."""
    if not pem:
        return None
    # Strip PEM headers and decode
    lines = [line for line in pem.strip().splitlines() if not line.startswith("-----")]
    import base64

    der_bytes = base64.b64decode("".join(lines))
    digest = hashlib.sha256(der_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _compute_metadata_diff(
    current_row: dict,
    parsed: dict,
    new_attribute_mapping: dict[str, str] | None,
) -> list[SPMetadataFieldChange]:
    """Compare current SP row against parsed metadata and return changes.

    Raises ValidationError if entity_id changed.
    """
    if parsed["entity_id"] != current_row["entity_id"]:
        raise ValidationError(
            message=(
                f"Entity ID changed from '{current_row['entity_id']}' "
                f"to '{parsed['entity_id']}'. "
                "Entity ID changes require deleting and re-creating the SP."
            ),
            code="sp_entity_id_changed",
        )

    changes: list[SPMetadataFieldChange] = []

    # Simple string fields
    field_map = {
        "acs_url": ("ACS URL", parsed.get("acs_url")),
        "slo_url": ("SLO URL", parsed.get("slo_url")),
        "nameid_format": (
            "NameID Format",
            parsed.get("nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        ),
    }

    for db_field, (display_name, new_val) in field_map.items():
        old_val = current_row.get(db_field)
        # Normalize None vs empty string
        old_norm = old_val or None
        new_norm = new_val or None
        if old_norm != new_norm:
            changes.append(
                SPMetadataFieldChange(
                    field=display_name,
                    old_value=old_norm,
                    new_value=new_norm,
                )
            )

    # Certificate: show fingerprints instead of full PEM
    old_cert = current_row.get("certificate_pem")
    new_cert = parsed.get("certificate_pem")
    if (old_cert or None) != (new_cert or None):
        changes.append(
            SPMetadataFieldChange(
                field="Certificate",
                old_value=_cert_fingerprint(old_cert) if old_cert else None,
                new_value=_cert_fingerprint(new_cert) if new_cert else None,
            )
        )

    # Encryption certificate: show fingerprints instead of full PEM
    old_enc_cert = current_row.get("encryption_certificate_pem")
    new_enc_cert = parsed.get("encryption_certificate_pem")
    if (old_enc_cert or None) != (new_enc_cert or None):
        changes.append(
            SPMetadataFieldChange(
                field="Encryption Certificate",
                old_value=_cert_fingerprint(old_enc_cert) if old_enc_cert else None,
                new_value=_cert_fingerprint(new_enc_cert) if new_enc_cert else None,
            )
        )

    # sp_requested_attributes: compare as JSON
    old_attrs = current_row.get("sp_requested_attributes")
    new_attrs = parsed.get("requested_attributes")
    old_attrs_json = json.dumps(old_attrs, sort_keys=True) if old_attrs else None
    new_attrs_json = json.dumps(new_attrs, sort_keys=True) if new_attrs else None
    if old_attrs_json != new_attrs_json:
        old_summary = f"{len(old_attrs)} attribute(s)" if old_attrs else None
        new_summary = f"{len(new_attrs)} attribute(s)" if new_attrs else None
        changes.append(
            SPMetadataFieldChange(
                field="Requested Attributes",
                old_value=old_summary,
                new_value=new_summary,
            )
        )

    # attribute_mapping: compare as JSON
    old_mapping = current_row.get("attribute_mapping")
    old_mapping_json = json.dumps(old_mapping, sort_keys=True) if old_mapping else None
    new_mapping_json = (
        json.dumps(new_attribute_mapping, sort_keys=True) if new_attribute_mapping else None
    )
    if old_mapping_json != new_mapping_json:
        old_keys = ", ".join(sorted(old_mapping.keys())) if old_mapping else None
        new_keys = (
            ", ".join(sorted(new_attribute_mapping.keys())) if new_attribute_mapping else None
        )
        changes.append(
            SPMetadataFieldChange(
                field="Attribute Mapping",
                old_value=old_keys,
                new_value=new_keys,
            )
        )

    return changes


def _parse_and_detect_mapping(
    metadata_xml: str,
) -> tuple[dict, dict[str, str] | None]:
    """Parse metadata XML and auto-detect attribute mapping.

    Returns (parsed_dict, attribute_mapping_or_none).
    """
    from utils.saml_idp import parse_sp_metadata_xml

    try:
        parsed = parse_sp_metadata_xml(metadata_xml)
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="sp_metadata_parse_error",
        )

    sp_requested_attributes = parsed.get("requested_attributes")
    attribute_mapping = None
    if sp_requested_attributes:
        from utils.saml_idp import auto_detect_attribute_mapping

        attribute_mapping = auto_detect_attribute_mapping(sp_requested_attributes) or None

    return parsed, attribute_mapping


def _apply_metadata_refresh(
    tenant_id: str,
    sp_id: str,
    parsed: dict,
    metadata_xml: str,
    attribute_mapping: dict[str, str] | None,
) -> dict:
    """Apply parsed metadata to an SP via refresh_sp_metadata_fields.

    Returns the updated database row.
    """
    row = database.service_providers.refresh_sp_metadata_fields(
        tenant_id=tenant_id,
        sp_id=sp_id,
        acs_url=parsed["acs_url"],
        certificate_pem=parsed.get("certificate_pem"),
        encryption_certificate_pem=parsed.get("encryption_certificate_pem"),
        nameid_format=parsed.get(
            "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        metadata_xml=metadata_xml,
        slo_url=parsed.get("slo_url"),
        sp_requested_attributes=parsed.get("requested_attributes"),
        attribute_mapping=attribute_mapping,
    )

    if row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    return row


def preview_sp_metadata_refresh(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPMetadataChangePreview:
    """Preview changes from refreshing metadata from the stored URL.

    Authorization: Requires super_admin role.
    """
    from utils.saml_idp import fetch_sp_metadata

    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    current = database.service_providers.get_service_provider(tenant_id, sp_id)
    if current is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    if not current.get("metadata_url"):
        raise ValidationError(
            message="This service provider has no metadata URL configured",
            code="sp_no_metadata_url",
        )

    try:
        metadata_xml = fetch_sp_metadata(current["metadata_url"])
    except ValueError as e:
        raise ValidationError(message=str(e), code="sp_metadata_fetch_error")

    parsed, attribute_mapping = _parse_and_detect_mapping(metadata_xml)
    changes = _compute_metadata_diff(current, parsed, attribute_mapping)

    return SPMetadataChangePreview(
        sp_id=str(current["id"]),
        sp_name=current["name"],
        source="url",
        changes=changes,
        has_changes=len(changes) > 0,
    )


def apply_sp_metadata_refresh(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPConfig:
    """Re-fetch metadata from URL and apply changes.

    Authorization: Requires super_admin role.
    Logs: sp_metadata_refreshed event.
    """
    from utils.saml_idp import fetch_sp_metadata

    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    current = database.service_providers.get_service_provider(tenant_id, sp_id)
    if current is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    if not current.get("metadata_url"):
        raise ValidationError(
            message="This service provider has no metadata URL configured",
            code="sp_no_metadata_url",
        )

    try:
        metadata_xml = fetch_sp_metadata(current["metadata_url"])
    except ValueError as e:
        raise ValidationError(message=str(e), code="sp_metadata_fetch_error")

    parsed, attribute_mapping = _parse_and_detect_mapping(metadata_xml)

    # Validate entity_id hasn't changed
    if parsed["entity_id"] != current["entity_id"]:
        raise ValidationError(
            message=(
                f"Entity ID changed from '{current['entity_id']}' "
                f"to '{parsed['entity_id']}'. "
                "Entity ID changes require deleting and re-creating the SP."
            ),
            code="sp_entity_id_changed",
        )

    row = _apply_metadata_refresh(tenant_id, sp_id, parsed, metadata_xml, attribute_mapping)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="sp_metadata_refreshed",
        metadata={"name": current["name"], "metadata_url": current["metadata_url"]},
    )

    config = _row_to_config(row)
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]
    return config


def preview_sp_metadata_reimport(
    requesting_user: RequestingUser,
    sp_id: str,
    metadata_xml: str,
) -> SPMetadataChangePreview:
    """Preview changes from re-importing metadata from provided XML.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    current = database.service_providers.get_service_provider(tenant_id, sp_id)
    if current is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    parsed, attribute_mapping = _parse_and_detect_mapping(metadata_xml)
    changes = _compute_metadata_diff(current, parsed, attribute_mapping)

    return SPMetadataChangePreview(
        sp_id=str(current["id"]),
        sp_name=current["name"],
        source="xml",
        changes=changes,
        has_changes=len(changes) > 0,
    )


def apply_sp_metadata_reimport(
    requesting_user: RequestingUser,
    sp_id: str,
    metadata_xml: str,
) -> SPConfig:
    """Parse provided XML and apply metadata changes.

    Authorization: Requires super_admin role.
    Logs: sp_metadata_reimported event.
    """
    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    current = database.service_providers.get_service_provider(tenant_id, sp_id)
    if current is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    parsed, attribute_mapping = _parse_and_detect_mapping(metadata_xml)

    # Validate entity_id hasn't changed
    if parsed["entity_id"] != current["entity_id"]:
        raise ValidationError(
            message=(
                f"Entity ID changed from '{current['entity_id']}' "
                f"to '{parsed['entity_id']}'. "
                "Entity ID changes require deleting and re-creating the SP."
            ),
            code="sp_entity_id_changed",
        )

    row = _apply_metadata_refresh(tenant_id, sp_id, parsed, metadata_xml, attribute_mapping)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="sp_metadata_reimported",
        metadata={"name": current["name"]},
    )

    config = _row_to_config(row)
    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert:
        config.signing_cert_expires_at = cert["expires_at"]
    return config
