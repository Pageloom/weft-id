"""IdP metadata import and refresh operations.

This module handles fetching, parsing, and refreshing IdP metadata
from metadata URLs or raw XML content.
"""

import logging

import database
from schemas.saml import (
    IdPConfig,
    IdPCreate,
    IdPMetadataParsed,
    MetadataRefreshResult,
    MetadataRefreshSummary,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.saml._converters import idp_row_to_config
from services.saml.providers import create_identity_provider
from services.types import RequestingUser
from utils.saml import fetch_idp_metadata, parse_idp_metadata_xml

logger = logging.getLogger(__name__)


def fetch_and_parse_idp_metadata(url: str) -> IdPMetadataParsed:
    """
    Fetch and parse IdP metadata from URL.

    No authorization required (used during import flow).

    Args:
        url: Metadata URL

    Returns:
        IdPMetadataParsed with entity_id, sso_url, slo_url, certificate_pem

    Raises:
        ValidationError if fetch fails or metadata is invalid
    """
    try:
        xml_content = fetch_idp_metadata(url)
        parsed = parse_idp_metadata_xml(xml_content)

        return IdPMetadataParsed(
            entity_id=parsed["entity_id"],
            sso_url=parsed["sso_url"],
            slo_url=parsed["slo_url"],
            certificate_pem=parsed["certificate_pem"],
        )
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="metadata_fetch_failed",
        ) from e


def import_idp_from_metadata_url(
    requesting_user: RequestingUser,
    name: str,
    provider_type: str,
    metadata_url: str,
    base_url: str,
) -> IdPConfig:
    """
    Import and create an IdP from metadata URL.

    Authorization: Requires super_admin role.

    Fetches metadata, parses it, and creates the IdP configuration.
    The metadata_url is stored for future auto-refresh.

    Returns:
        Created IdPConfig
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Fetch and parse metadata
    metadata = fetch_and_parse_idp_metadata(metadata_url)

    # Create IdP using parsed metadata
    data = IdPCreate(
        name=name,
        provider_type=provider_type,
        entity_id=metadata.entity_id,
        sso_url=metadata.sso_url,
        slo_url=metadata.slo_url,
        certificate_pem=metadata.certificate_pem,
        metadata_url=metadata_url,
        is_enabled=False,  # Start disabled, admin must enable
    )

    return create_identity_provider(requesting_user, data, base_url)


def parse_idp_metadata_xml_to_schema(metadata_xml: str) -> IdPMetadataParsed:
    """
    Parse raw IdP metadata XML directly.

    No authorization required (used during import flow).

    Args:
        metadata_xml: Raw SAML metadata XML content

    Returns:
        IdPMetadataParsed with entity_id, sso_url, slo_url, certificate_pem

    Raises:
        ValidationError if metadata is invalid
    """
    try:
        parsed = parse_idp_metadata_xml(metadata_xml)

        return IdPMetadataParsed(
            entity_id=parsed["entity_id"],
            sso_url=parsed["sso_url"],
            slo_url=parsed["slo_url"],
            certificate_pem=parsed["certificate_pem"],
        )
    except ValueError as e:
        raise ValidationError(
            message=str(e),
            code="metadata_parse_failed",
        ) from e


def import_idp_from_metadata_xml(
    requesting_user: RequestingUser,
    name: str,
    provider_type: str,
    metadata_xml: str,
    base_url: str,
) -> IdPConfig:
    """
    Import and create an IdP from raw metadata XML.

    Authorization: Requires super_admin role.

    Parses the XML and creates the IdP configuration.
    No metadata_url is stored since this is a direct XML import.

    Returns:
        Created IdPConfig
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Parse metadata XML directly
    metadata = parse_idp_metadata_xml_to_schema(metadata_xml)

    # Create IdP using parsed metadata (no metadata_url since imported from XML)
    data = IdPCreate(
        name=name,
        provider_type=provider_type,
        entity_id=metadata.entity_id,
        sso_url=metadata.sso_url,
        slo_url=metadata.slo_url,
        certificate_pem=metadata.certificate_pem,
        metadata_url=None,  # No URL to store - imported from raw XML
        is_enabled=False,  # Start disabled, admin must enable
    )

    return create_identity_provider(requesting_user, data, base_url)


def refresh_idp_from_metadata(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPConfig:
    """
    Manually refresh an IdP from its metadata URL.

    Authorization: Requires super_admin role.

    Returns:
        Updated IdPConfig

    Raises:
        ValidationError if IdP has no metadata URL or refresh fails
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get current IdP
    existing = database.saml.get_identity_provider(tenant_id, idp_id)
    if existing is None:
        raise NotFoundError(
            message="Identity provider not found",
            code="idp_not_found",
        )

    if not existing["metadata_url"]:
        raise ValidationError(
            message="Identity provider has no metadata URL configured",
            code="no_metadata_url",
        )

    # Fetch and parse metadata
    try:
        metadata = fetch_and_parse_idp_metadata(existing["metadata_url"])
    except ValidationError:
        raise

    # Update IdP with new metadata
    row = database.saml.update_idp_metadata_fields(
        tenant_id=tenant_id,
        idp_id=idp_id,
        entity_id=metadata.entity_id,
        sso_url=metadata.sso_url,
        certificate_pem=metadata.certificate_pem,
        slo_url=metadata.slo_url,
    )

    if row is None:
        raise ValidationError(
            message="Failed to update identity provider",
            code="idp_update_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_identity_provider",
        artifact_id=idp_id,
        event_type="saml_idp_metadata_refreshed",
        metadata={"name": existing["name"], "manual": True},
    )

    return idp_row_to_config(row)


def refresh_all_idp_metadata() -> MetadataRefreshSummary:
    """
    Refresh metadata for all IdPs that have a metadata URL.

    Used by background job. No authorization required.

    Returns:
        MetadataRefreshSummary with results for each IdP
    """
    idps = database.saml.get_idps_with_metadata_url()
    results: list[MetadataRefreshResult] = []
    successful = 0
    failed = 0

    for idp in idps:
        idp_id = str(idp["id"])
        tenant_id = str(idp["tenant_id"])
        idp_name = idp["name"]
        metadata_url = idp["metadata_url"]

        try:
            # Fetch and parse metadata
            metadata = fetch_and_parse_idp_metadata(metadata_url)

            # Get current values to determine what changed
            current = database.saml.get_identity_provider(tenant_id, idp_id)
            if current is None:
                raise ValueError("IdP not found")

            updated_fields = []
            if current["entity_id"] != metadata.entity_id:
                updated_fields.append("entity_id")
            if current["sso_url"] != metadata.sso_url:
                updated_fields.append("sso_url")
            if current["slo_url"] != metadata.slo_url:
                updated_fields.append("slo_url")
            if current["certificate_pem"] != metadata.certificate_pem:
                updated_fields.append("certificate_pem")

            # Update IdP with new metadata
            # NOTE: No log_event here - background metadata sync is exempt from audit
            # logging. These are automated system operations, not user actions.
            database.saml.update_idp_metadata_fields(
                tenant_id=tenant_id,
                idp_id=idp_id,
                entity_id=metadata.entity_id,
                sso_url=metadata.sso_url,
                certificate_pem=metadata.certificate_pem,
                slo_url=metadata.slo_url,
            )

            results.append(
                MetadataRefreshResult(
                    idp_id=idp_id,
                    idp_name=idp_name,
                    success=True,
                    updated_fields=updated_fields if updated_fields else None,
                )
            )
            successful += 1

            logger.info(f"Refreshed SAML metadata for IdP {idp_name} ({idp_id})")

        except Exception as e:
            error_msg = str(e)[:200]  # Truncate long errors

            # Set error on IdP (but don't disable it)
            # NOTE: No log_event - background sync errors are exempt from audit logging
            database.saml.set_idp_metadata_error(tenant_id, idp_id, error_msg)

            results.append(
                MetadataRefreshResult(
                    idp_id=idp_id,
                    idp_name=idp_name,
                    success=False,
                    error=error_msg,
                )
            )
            failed += 1

            logger.warning(f"Failed to refresh SAML metadata for IdP {idp_name}: {error_msg}")

    return MetadataRefreshSummary(
        total=len(idps),
        successful=successful,
        failed=failed,
        results=results,
    )
