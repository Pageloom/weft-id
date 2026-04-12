"""Redact PII from verbose SAML assertion event logs.

Verbose logging stores full user attributes (email, name, groups) in
event log metadata so admins can diagnose SAML mapping issues. After
the 24-hour debug window expires, this job replaces PII with redaction
markers while preserving structural info (counts, field names) for the
audit trail.

Called by the worker's periodic timer (hourly, same cadence as the
companion saml_debug_entries cleanup).
"""

import logging
from datetime import UTC, datetime
from typing import Any

import database
from utils.request_metadata import compute_metadata_hash

logger = logging.getLogger(__name__)

# String fields that contain PII
_PII_STRING_FIELDS = ("email", "first_name", "last_name", "name_id")

_REDACTED = "[redacted]"


def _redact_pii(metadata: dict[str, Any]) -> dict[str, Any]:
    """Replace PII fields with redaction markers.

    String PII fields become "[redacted]".
    Collection fields (groups, unmapped_attributes) become
    {"count": N, "redacted": true} to preserve diagnostic info.
    """
    result = dict(metadata)

    for field in _PII_STRING_FIELDS:
        if field in result and result[field] is not None:
            result[field] = _REDACTED

    # Replace groups list with count
    if "groups" in result and isinstance(result["groups"], list):
        result["groups"] = {"count": len(result["groups"]), "redacted": True}

    # Replace unmapped_attributes dict with count
    if "unmapped_attributes" in result and isinstance(result["unmapped_attributes"], dict):
        attrs = result["unmapped_attributes"]
        if not attrs.get("redacted"):
            result["unmapped_attributes"] = {"count": len(attrs), "redacted": True}

    result["pii_redacted_at"] = datetime.now(UTC).isoformat()

    return result


def redact_verbose_event_pii() -> dict[str, Any]:
    """Redact PII from saml_assertion_received events older than 24h.

    Processes all pending events (in batches of 100) to ensure nothing
    is left behind between hourly runs.
    """
    total_redacted = 0
    old_hashes: set[str] = set()

    while True:
        events = database.event_log.get_unredacted_verbose_events(batch_size=100)
        if not events:
            break

        for event in events:
            metadata = dict(event["metadata"])
            old_hash = event["metadata_hash"]

            redacted_metadata = _redact_pii(metadata)
            new_hash = compute_metadata_hash(redacted_metadata)

            database.event_log.swap_event_metadata(
                event_id=str(event["id"]),
                new_hash=new_hash,
                new_metadata=redacted_metadata,
            )

            old_hashes.add(old_hash)
            total_redacted += 1

    # Clean up metadata rows that are no longer referenced
    if old_hashes:
        deleted_metadata = database.event_log.delete_orphaned_metadata(list(old_hashes))
        if deleted_metadata:
            logger.info("Deleted %d orphaned metadata rows", deleted_metadata)

    if total_redacted:
        logger.info("Redacted PII from %d verbose assertion events", total_redacted)

    return {"redacted": total_redacted}
