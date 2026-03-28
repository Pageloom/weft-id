"""Continuous HIBP breach monitoring for passwords.

Periodically queries the Have I Been Pwned API to detect passwords that
appeared in breaches after they were set. Uses the stored SHA-1 prefix
and HMAC to check without knowing the actual password.
"""

import logging
import time
from typing import Any

import database
import httpx
from database._core import session
from services.event_log import SYSTEM_ACTOR_ID, log_event
from utils.crypto import derive_hmac_key
from utils.email import send_hibp_breach_admin_notification
from utils.password_strength import (
    HIBP_API_URL,
    HIBP_TIMEOUT_SECONDS,
    check_hibp_suffix_against_hmac,
)
from utils.request_context import system_context

logger = logging.getLogger(__name__)

# HIBP free tier: max 1 request per 1.5 seconds
HIBP_RATE_LIMIT_SECONDS = 1.5


def _fetch_hibp_suffixes(prefix: str) -> list[str]:
    """Query HIBP API and return the list of SHA-1 suffixes for a prefix.

    Returns an empty list on network error or timeout.
    """
    try:
        response = httpx.get(
            f"{HIBP_API_URL}{prefix}",
            timeout=HIBP_TIMEOUT_SECONDS,
            headers={"User-Agent": "WeftID-BreachMonitor"},
        )
        response.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException):
        logger.warning("HIBP API unreachable for prefix %s, skipping", prefix)
        return []

    suffixes = []
    for line in response.text.splitlines():
        hash_suffix, _, _ = line.partition(":")
        suffixes.append(hash_suffix.strip())
    return suffixes


def check_hibp_breaches() -> dict[str, Any]:
    """Check all tenants for passwords that have appeared in HIBP breaches.

    For each user with stored HIBP monitoring data:
    1. Query HIBP with the stored prefix
    2. Compare returned suffixes against the stored HMAC
    3. On match: set password_reset_required, clear HIBP data,
       revoke OAuth2 tokens, log event, notify admins

    This function is called directly by the worker's periodic timer (weekly).

    Returns:
        Dict with tenants_processed, breaches_found, and details
    """
    logger.info("Starting HIBP breach check...")

    # Get all tenant IDs that have password users
    tenants = database.security.get_all_tenant_ids()
    if not tenants:
        logger.info("No tenants found")
        return {"tenants_processed": 0, "breaches_found": 0, "details": []}

    hmac_key = derive_hmac_key("hibp")
    total_breaches = 0
    details = []

    # Cache HIBP responses by prefix to avoid duplicate API calls
    prefix_cache: dict[str, list[str]] = {}

    for tenant in tenants:
        tenant_id = str(tenant["tenant_id"])

        try:
            with session(tenant_id=tenant_id):
                result = _process_tenant(tenant_id, hmac_key, prefix_cache)
                total_breaches += result["count"]
                if result["count"] > 0:
                    details.append(
                        {
                            "tenant_id": tenant_id,
                            "breaches_found": result["count"],
                            "user_ids": result["user_ids"],
                        }
                    )
        except Exception as e:
            logger.exception(
                "Failed to process tenant %s for HIBP breach check: %s",
                tenant_id,
                e,
            )
            details.append({"tenant_id": tenant_id, "error": str(e)})

    logger.info(
        "HIBP breach check completed: %d tenants processed, %d breaches found",
        len(tenants),
        total_breaches,
    )

    return {
        "tenants_processed": len(tenants),
        "breaches_found": total_breaches,
        "details": details,
    }


def _process_tenant(
    tenant_id: str,
    hmac_key: bytes,
    prefix_cache: dict[str, list[str]],
) -> dict[str, Any]:
    """Process a single tenant for HIBP breach detection.

    Args:
        tenant_id: Tenant ID to process
        hmac_key: HKDF-derived key for HMAC verification
        prefix_cache: Shared cache of HIBP responses by prefix

    Returns:
        Dict with count and user_ids of breached users
    """
    users = database.users.get_users_with_hibp_prefix(tenant_id)
    if not users:
        return {"count": 0, "user_ids": []}

    logger.info("Tenant %s: checking %d users against HIBP", tenant_id, len(users))

    breached_user_ids = []

    with system_context():
        for user in users:
            user_id = str(user["id"])
            prefix = user["hibp_prefix"]
            stored_hmac = user["hibp_check_hmac"]

            # Fetch suffixes (with caching and rate limiting)
            if prefix not in prefix_cache:
                suffixes = _fetch_hibp_suffixes(prefix)
                prefix_cache[prefix] = suffixes
                # Respect HIBP rate limit
                time.sleep(HIBP_RATE_LIMIT_SECONDS)
            else:
                suffixes = prefix_cache[prefix]

            if not suffixes:
                continue

            # Check if any suffix matches our stored HMAC
            if check_hibp_suffix_against_hmac(prefix, stored_hmac, hmac_key, suffixes):
                logger.warning(
                    "Tenant %s: user %s password found in HIBP breach",
                    tenant_id,
                    user_id,
                )

                # Flag user for password reset
                database.users.set_password_reset_required(tenant_id, user_id, True)
                database.users.clear_hibp_data(tenant_id, user_id)

                # Revoke OAuth2 tokens
                revoked = database.oauth2.revoke_all_user_tokens(tenant_id, user_id)
                if revoked > 0:
                    log_event(
                        tenant_id=tenant_id,
                        actor_user_id=SYSTEM_ACTOR_ID,
                        event_type="oauth2_user_tokens_revoked",
                        artifact_type="user",
                        artifact_id=user_id,
                        metadata={"reason": "hibp_breach", "tokens_revoked": revoked},
                    )

                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=SYSTEM_ACTOR_ID,
                    event_type="password_breach_detected",
                    artifact_type="user",
                    artifact_id=user_id,
                )

                breached_user_ids.append(user_id)

    # Notify admins if breaches were found
    if breached_user_ids:
        _notify_admins(tenant_id, len(breached_user_ids))

    return {"count": len(breached_user_ids), "user_ids": breached_user_ids}


def _notify_admins(tenant_id: str, breach_count: int) -> None:
    """Send email notification to admins about detected breaches."""
    admin_emails = database.users.get_admin_emails(tenant_id)
    for email in admin_emails:
        try:
            send_hibp_breach_admin_notification(email, breach_count, tenant_id=tenant_id)
        except Exception:
            logger.exception("Failed to send breach notification to %s", email)
