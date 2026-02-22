"""Group graph layout database operations."""

from database._core import TenantArg, execute, fetchone
from psycopg.types.json import Json


def get_graph_layout(tenant_id: TenantArg, user_id: str) -> dict | None:
    row = fetchone(
        tenant_id,
        "SELECT node_ids, positions FROM group_graph_layouts WHERE user_id = :user_id",
        {"user_id": user_id},
    )
    if not row:
        return None
    return {"node_ids": row["node_ids"], "positions": row["positions"]}


def upsert_graph_layout(tenant_id: TenantArg, user_id: str, node_ids: str, positions: dict) -> None:
    execute(
        tenant_id,
        """
        INSERT INTO group_graph_layouts (tenant_id, user_id, node_ids, positions, updated_at)
        VALUES (:tenant_id, :user_id, :node_ids, :positions, now())
        ON CONFLICT (tenant_id, user_id) DO UPDATE SET
            node_ids = EXCLUDED.node_ids,
            positions = EXCLUDED.positions,
            updated_at = now()
        """,
        {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "node_ids": node_ids,
            "positions": Json(positions),
        },
    )
