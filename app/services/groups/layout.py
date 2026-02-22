"""Group graph layout service functions."""

import database
from schemas.groups import GroupGraphLayout
from services.activity import track_activity
from services.auth import require_admin
from services.types import RequestingUser


def get_graph_layout(requesting_user: RequestingUser) -> GroupGraphLayout | None:
    """Authorization: Requires admin role."""
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    row = database.groups.get_graph_layout(requesting_user["tenant_id"], requesting_user["id"])
    if not row:
        return None
    return GroupGraphLayout(node_ids=row["node_ids"], positions=row["positions"])


def save_graph_layout(requesting_user: RequestingUser, layout: GroupGraphLayout) -> None:
    """Authorization: Requires admin role.

    No audit: layout is UI preference state, not a business action.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    database.groups.upsert_graph_layout(
        requesting_user["tenant_id"],
        requesting_user["id"],
        layout.node_ids,
        layout.positions,
    )
