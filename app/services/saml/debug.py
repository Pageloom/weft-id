"""SAML debug entry storage.

This module handles storage and retrieval of SAML authentication failures
for debugging purposes. Entries are automatically cleaned up after 24 hours.
"""

import base64
import logging

import database
from services.activity import track_activity
from services.auth import require_super_admin
from services.exceptions import NotFoundError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def store_saml_debug_entry(
    tenant_id: str,
    error_type: str,
    error_detail: str | None = None,
    idp_id: str | None = None,
    idp_name: str | None = None,
    saml_response_b64: str | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
    verbose_event_logging: bool = False,
) -> str | None:
    """
    Store a SAML authentication failure for debugging.

    No authorization required (called from authentication flow).

    This stores the failure details for super admins to review.
    Entries are automatically cleaned up after 24 hours.

    Args:
        tenant_id: Tenant ID
        error_type: Type of error (signature_error, expired, invalid_response, etc.)
        error_detail: Detailed error message
        idp_id: IdP UUID if known
        idp_name: IdP name for display
        saml_response_b64: Raw base64-encoded SAML response
        request_ip: Client IP address
        user_agent: Client user agent
        verbose_event_logging: When True, also log a saml_assertion_failed event

    Returns:
        Debug entry ID string, or None on failure.
    """
    # Try to decode the XML for easier viewing
    saml_response_xml = None
    if saml_response_b64:
        try:
            saml_response_xml = base64.b64decode(saml_response_b64).decode("utf-8")
        except Exception:
            pass  # Keep XML as None if decoding fails

    try:
        entry = database.saml.store_debug_entry(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            error_type=error_type,
            error_detail=error_detail,
            idp_id=idp_id,
            idp_name=idp_name,
            saml_response_b64=saml_response_b64,
            saml_response_xml=saml_response_xml,
            request_ip=request_ip,
            user_agent=user_agent,
        )
        debug_entry_id = str(entry["id"]) if entry else None

        if verbose_event_logging and debug_entry_id and idp_id:
            try:
                from services.event_log import SYSTEM_ACTOR_ID, log_event

                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=SYSTEM_ACTOR_ID,
                    artifact_type="saml_identity_provider",
                    artifact_id=idp_id,
                    event_type="saml_assertion_failed",
                    metadata={
                        "idp_name": idp_name,
                        "error_type": error_type,
                        "error_detail": error_detail[:500] if error_detail else None,
                        "debug_entry_id": debug_entry_id,
                    },
                )
            except Exception as e:
                logger.warning(f"Failed to log verbose assertion failure event: {e}")

        return debug_entry_id
    except Exception as e:
        # Don't let debug storage failures affect authentication
        logger.warning(f"Failed to store SAML debug entry: {e}")
        return None


def list_saml_debug_entries(
    requesting_user: RequestingUser,
    limit: int = 50,
) -> list[dict]:
    """
    List recent SAML debug entries.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user
        limit: Maximum entries to return

    Returns:
        List of debug entry dicts
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    return database.saml.get_debug_entries(requesting_user["tenant_id"], limit)


def get_saml_debug_entry(
    requesting_user: RequestingUser,
    entry_id: str,
) -> dict:
    """
    Get a specific SAML debug entry.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user
        entry_id: Debug entry UUID

    Returns:
        Debug entry dict

    Raises:
        NotFoundError if entry doesn't exist
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    entry = database.saml.get_debug_entry(requesting_user["tenant_id"], entry_id)
    if entry is None:
        raise NotFoundError(
            message="Debug entry not found",
            code="debug_entry_not_found",
        )

    return entry
