"""Event log database operations.

This module provides database-level operations for the event_logs table.
It is used by the service layer to persist audit log entries.
"""

from typing import Any

from psycopg.types.json import Json

from ._core import TenantArg, fetchall, fetchone, UNSCOPED


def create_event(
    tenant_id: TenantArg,
    tenant_id_value: str,
    actor_user_id: str,
    artifact_type: str,
    artifact_id: str,
    event_type: str,
    combined_metadata: dict[str, Any],
    metadata_hash: str,
) -> dict | None:
    """
    Create an event log entry with deduplicated metadata.

    Args:
        tenant_id: Tenant ID for RLS scoping
        tenant_id_value: The actual tenant ID value to store
        actor_user_id: User ID who performed the action (or SYSTEM_ACTOR_ID)
        artifact_type: Type of entity (e.g., "user", "privileged_domain")
        artifact_id: UUID of the affected entity
        event_type: Descriptive event type (e.g., "user_created")
        combined_metadata: Full metadata dict (request fields + custom event data)
        metadata_hash: MD5 hash of combined_metadata for deduplication

    Returns:
        Dict with id and created_at, or None if insert failed
    """
    # First, insert metadata into event_log_metadata table (ON CONFLICT DO NOTHING for dedup)
    # Note: event_log_metadata is a global table (no tenant_id), so use UNSCOPED
    fetchone(
        UNSCOPED,
        """
        INSERT INTO event_log_metadata (metadata_hash, metadata)
        VALUES (:metadata_hash, :metadata)
        ON CONFLICT (metadata_hash) DO NOTHING
        """,
        {
            "metadata_hash": metadata_hash,
            "metadata": Json(combined_metadata),
        },
    )

    # Then insert event with metadata_hash reference
    return fetchone(
        tenant_id,
        """
        INSERT INTO event_logs
            (tenant_id, actor_user_id, artifact_type, artifact_id, event_type, metadata_hash)
        VALUES
            (:tenant_id, :actor_user_id, :artifact_type, :artifact_id, :event_type, :metadata_hash)
        RETURNING id, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "actor_user_id": actor_user_id,
            "artifact_type": artifact_type,
            "artifact_id": artifact_id,
            "event_type": event_type,
            "metadata_hash": metadata_hash,
        },
    )


def list_events(
    tenant_id: TenantArg,
    limit: int = 100,
    offset: int = 0,
    artifact_type: str | None = None,
    artifact_id: str | None = None,
    actor_user_id: str | None = None,
    event_type: str | None = None,
) -> list[dict]:
    """
    List event logs with optional filtering.

    Args:
        tenant_id: Tenant ID for RLS scoping
        limit: Max results to return
        offset: Number of results to skip
        artifact_type: Filter by artifact type
        artifact_id: Filter by artifact ID
        actor_user_id: Filter by actor
        event_type: Filter by event type

    Returns:
        List of event log dicts
    """
    where_clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if artifact_type:
        where_clauses.append("artifact_type = :artifact_type")
        params["artifact_type"] = artifact_type
    if artifact_id:
        where_clauses.append("artifact_id = :artifact_id")
        params["artifact_id"] = artifact_id
    if actor_user_id:
        where_clauses.append("actor_user_id = :actor_user_id")
        params["actor_user_id"] = actor_user_id
    if event_type:
        where_clauses.append("event_type = :event_type")
        params["event_type"] = event_type

    where_clause = ""
    if where_clauses:
        where_clause = "WHERE " + " AND ".join(where_clauses)

    return fetchall(
        tenant_id,
        f"""
        SELECT e.id, e.tenant_id, e.actor_user_id, e.artifact_type, e.artifact_id,
               e.event_type, e.created_at, e.metadata_hash,
               m.metadata,
               u.first_name as artifact_first_name,
               u.last_name as artifact_last_name,
               ue.email as artifact_email
        FROM event_logs e
        LEFT JOIN event_log_metadata m ON e.metadata_hash = m.metadata_hash
        LEFT JOIN users u ON (e.artifact_type = 'user' AND e.artifact_id = u.id)
        LEFT JOIN user_emails ue ON (e.artifact_type = 'user' AND e.artifact_id = ue.user_id AND ue.is_primary = true)
        {where_clause}
        ORDER BY e.created_at DESC
        LIMIT :limit OFFSET :offset
        """,
        params,
    )


def count_events(
    tenant_id: TenantArg,
    artifact_type: str | None = None,
    artifact_id: str | None = None,
) -> int:
    """
    Count event logs with optional filtering.

    Args:
        tenant_id: Tenant ID for RLS scoping
        artifact_type: Filter by artifact type
        artifact_id: Filter by artifact ID

    Returns:
        Total count of matching events
    """
    where_clauses: list[str] = []
    params: dict[str, Any] = {}

    if artifact_type:
        where_clauses.append("artifact_type = :artifact_type")
        params["artifact_type"] = artifact_type
    if artifact_id:
        where_clauses.append("artifact_id = :artifact_id")
        params["artifact_id"] = artifact_id

    where_clause = ""
    if where_clauses:
        where_clause = "WHERE " + " AND ".join(where_clauses)

    result = fetchone(
        tenant_id,
        f"SELECT count(*) as count FROM event_logs {where_clause}",
        params,
    )
    return result["count"] if result else 0


def get_event_by_id(tenant_id: TenantArg, event_id: str) -> dict | None:
    """
    Get a single event log entry by ID.

    Args:
        tenant_id: Tenant ID for RLS scoping
        event_id: The event log ID

    Returns:
        Event log dict or None if not found
    """
    return fetchone(
        tenant_id,
        """
        SELECT e.id, e.tenant_id, e.actor_user_id, e.artifact_type, e.artifact_id,
               e.event_type, e.created_at, e.metadata_hash,
               m.metadata,
               u.first_name as artifact_first_name,
               u.last_name as artifact_last_name,
               ue.email as artifact_email
        FROM event_logs e
        LEFT JOIN event_log_metadata m ON e.metadata_hash = m.metadata_hash
        LEFT JOIN users u ON (e.artifact_type = 'user' AND e.artifact_id = u.id)
        LEFT JOIN user_emails ue ON (e.artifact_type = 'user' AND e.artifact_id = ue.user_id AND ue.is_primary = true)
        WHERE e.id = :event_id
        """,
        {"event_id": event_id},
    )
