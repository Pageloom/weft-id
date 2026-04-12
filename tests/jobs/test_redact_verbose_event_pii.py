"""Tests for verbose SAML assertion event PII redaction job."""

from uuid import uuid4

import database
from psycopg.types.json import Json
from services.event_log import SYSTEM_ACTOR_ID
from utils.request_metadata import compute_metadata_hash


def _insert_verbose_event(tenant_id: str, idp_id: str, age_hours: int = 25) -> str:
    """Insert a saml_assertion_received event with PII metadata.

    Returns the event ID.
    """
    metadata = {
        "device": None,
        "user_agent": None,
        "remote_address": None,
        "session_id_hash": None,
        "api_client_id": None,
        "api_client_name": None,
        "api_client_type": None,
        "idp_name": "Test IdP",
        "email": "alice@example.com",
        "first_name": "Alice",
        "last_name": "Smith",
        "groups": ["Engineering", "Platform"],
        "name_id": "alice@example.com",
        "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "unmapped_attributes": {
            "email": ["alice@example.com"],
            "firstName": ["Alice"],
            "lastName": ["Smith"],
        },
        "debug_entry_id": str(uuid4()),
    }
    metadata_hash = compute_metadata_hash(metadata)

    database.event_log.execute(
        database.UNSCOPED,
        """
        INSERT INTO event_log_metadata (metadata_hash, metadata)
        VALUES (:metadata_hash, :metadata)
        ON CONFLICT (metadata_hash) DO NOTHING
        """,
        {"metadata_hash": metadata_hash, "metadata": Json(metadata)},
    )

    row = database.event_log.fetchone(
        tenant_id,
        """
        INSERT INTO event_logs
            (tenant_id, actor_user_id, artifact_type, artifact_id,
             event_type, metadata_hash, created_at)
        VALUES
            (:tenant_id, :actor_user_id, 'saml_identity_provider', :artifact_id,
             'saml_assertion_received', :metadata_hash,
             now() - make_interval(hours => :age_hours))
        RETURNING id
        """,
        {
            "tenant_id": tenant_id,
            "actor_user_id": SYSTEM_ACTOR_ID,
            "artifact_id": idp_id,
            "metadata_hash": metadata_hash,
            "age_hours": age_hours,
        },
    )
    return str(row["id"])


def test_redacts_old_verbose_events(test_tenant):
    """Events older than 24h should have PII fields redacted."""
    from jobs.redact_verbose_event_pii import redact_verbose_event_pii

    tenant_id = test_tenant["id"]
    idp_id = str(uuid4())
    event_id = _insert_verbose_event(tenant_id, idp_id, age_hours=25)

    result = redact_verbose_event_pii()

    assert result["redacted"] >= 1

    # Verify the event metadata was redacted
    event = database.event_log.get_event_by_id(tenant_id, event_id)
    metadata = event["metadata"]

    assert metadata["email"] == "[redacted]"
    assert metadata["first_name"] == "[redacted]"
    assert metadata["last_name"] == "[redacted]"
    assert metadata["name_id"] == "[redacted]"
    assert metadata["groups"] == {"count": 2, "redacted": True}
    assert metadata["unmapped_attributes"] == {"count": 3, "redacted": True}
    assert "pii_redacted_at" in metadata

    # Non-PII fields should be preserved
    assert metadata["idp_name"] == "Test IdP"
    assert metadata["name_id_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert "debug_entry_id" in metadata


def test_skips_recent_events(test_tenant):
    """Events less than 24h old should not be redacted."""
    from jobs.redact_verbose_event_pii import redact_verbose_event_pii

    tenant_id = test_tenant["id"]
    idp_id = str(uuid4())
    event_id = _insert_verbose_event(tenant_id, idp_id, age_hours=12)

    redact_verbose_event_pii()

    # Verify the event was NOT redacted
    event = database.event_log.get_event_by_id(tenant_id, event_id)
    metadata = event["metadata"]

    assert metadata["email"] == "alice@example.com"
    assert metadata["first_name"] == "Alice"
    assert "pii_redacted_at" not in metadata


def test_skips_already_redacted_events(test_tenant):
    """Events that were already redacted should not be processed again."""
    from jobs.redact_verbose_event_pii import redact_verbose_event_pii

    tenant_id = test_tenant["id"]
    idp_id = str(uuid4())
    _insert_verbose_event(tenant_id, idp_id, age_hours=25)

    # First pass
    result1 = redact_verbose_event_pii()
    assert result1["redacted"] >= 1

    # Second pass should find nothing new
    result2 = redact_verbose_event_pii()
    assert result2["redacted"] == 0


def test_returns_zero_when_nothing_to_redact():
    """Should return zero when no unredacted events exist."""
    from jobs.redact_verbose_event_pii import redact_verbose_event_pii

    result = redact_verbose_event_pii()
    assert result["redacted"] >= 0


def test_cleans_up_orphaned_metadata(test_tenant):
    """Old metadata rows should be deleted after the event is re-pointed."""
    from jobs.redact_verbose_event_pii import redact_verbose_event_pii

    tenant_id = test_tenant["id"]
    idp_id = str(uuid4())
    event_id = _insert_verbose_event(tenant_id, idp_id, age_hours=25)

    # Get the original metadata hash
    event_before = database.event_log.get_event_by_id(tenant_id, event_id)
    old_hash = event_before["metadata_hash"]

    redact_verbose_event_pii()

    # Get the new metadata hash
    event_after = database.event_log.get_event_by_id(tenant_id, event_id)
    new_hash = event_after["metadata_hash"]

    assert old_hash != new_hash

    # The old metadata row should be gone (orphaned and cleaned up)
    old_row = database.event_log.fetchone(
        database.UNSCOPED,
        "SELECT 1 FROM event_log_metadata WHERE metadata_hash = :hash",
        {"hash": old_hash},
    )
    assert old_row is None


def test_redact_pii_handles_null_fields():
    """PII fields that are None should be left as-is (not replaced with [redacted])."""
    from jobs.redact_verbose_event_pii import _redact_pii

    metadata = {
        "idp_name": "Test",
        "email": "user@example.com",
        "first_name": None,
        "last_name": None,
        "name_id": None,
        "groups": [],
        "unmapped_attributes": {},
    }

    result = _redact_pii(metadata)

    assert result["email"] == "[redacted]"
    assert result["first_name"] is None
    assert result["last_name"] is None
    assert result["name_id"] is None
    assert result["groups"] == {"count": 0, "redacted": True}
    assert result["unmapped_attributes"] == {"count": 0, "redacted": True}
