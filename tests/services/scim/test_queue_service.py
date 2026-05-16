"""Tests for `services.scim.queue` thin wrappers.

These tests prove the wrappers thread the right `resource_type` string
into the underlying upsert. The dedupe / re-enqueue semantics live with
the database-layer tests in `tests/database/test_scim_push_queue.py`;
no need to re-test them here.
"""

from __future__ import annotations

from unittest.mock import patch

from services.scim import queue


def test_enqueue_user_passes_user_resource_type() -> None:
    with patch("services.scim.queue.database") as db:
        queue.enqueue_user("tenant-1", "sp-1", "user-1")

    db.scim_push_queue.upsert_entry.assert_called_once_with(
        tenant_id="tenant-1",
        tenant_id_value="tenant-1",
        sp_id="sp-1",
        resource_type="user",
        resource_id="user-1",
    )


def test_enqueue_group_passes_group_resource_type() -> None:
    with patch("services.scim.queue.database") as db:
        queue.enqueue_group("tenant-2", "sp-2", "group-2")

    db.scim_push_queue.upsert_entry.assert_called_once_with(
        tenant_id="tenant-2",
        tenant_id_value="tenant-2",
        sp_id="sp-2",
        resource_type="group",
        resource_id="group-2",
    )
