"""SAML IdP metadata auto-refresh job.

This module provides the scheduled job that refreshes SAML IdP metadata
from configured metadata URLs.
"""

import logging
from typing import Any

from services import saml as saml_service

logger = logging.getLogger(__name__)


def refresh_saml_metadata() -> dict[str, Any]:
    """
    Refresh SAML IdP metadata for all IdPs with metadata URLs.

    This function is called directly by the worker's periodic timer (daily),
    not as a queued job. It refreshes metadata across all tenants.

    For each IdP with a metadata_url configured:
    - Fetch metadata from the URL
    - Parse and update entity_id, sso_url, slo_url, certificate_pem
    - Update metadata_last_fetched_at on success
    - Set metadata_fetch_error on failure (IdP remains enabled)

    Returns:
        Dict with total, successful, failed counts and details
    """
    logger.info("Starting SAML IdP metadata refresh...")

    try:
        result = saml_service.refresh_all_idp_metadata()

        logger.info(
            "SAML metadata refresh completed: %d total, %d successful, %d failed",
            result.total,
            result.successful,
            result.failed,
        )

        return {
            "total": result.total,
            "successful": result.successful,
            "failed": result.failed,
            "results": [
                {
                    "idp_id": r.idp_id,
                    "idp_name": r.idp_name,
                    "success": r.success,
                    "error": r.error,
                    "updated_fields": r.updated_fields,
                }
                for r in result.results
            ],
        }

    except Exception as e:
        logger.exception("SAML metadata refresh failed: %s", e)
        return {
            "total": 0,
            "successful": 0,
            "failed": 0,
            "error": str(e),
        }
