"""Worker tests for the remote-id mapping iteration.

Cover the dispatch-layer behavior changes:

- First push: no mapping -> POST; capture `scim_id` from response and
  call `record_mapping`.
- Second push: mapping exists -> PUT against the receiver's `remote_id`,
  not POST.
- DELETE with mapping -> DELETE `/Users/<remote_id>` (not `/Users/<weftid_id>`).
- DELETE without mapping -> DELETE `/Users/<weftid_id>` (fallback for
  pre-mapping rows).
- 404 on PUT with mapping -> invalidate the mapping and reclassify the
  outcome as retryable so the next attempt POSTs cleanly.
- 404 on DELETE with mapping (`absent`) -> drop the queue row, mark
  sync_log `done` with the `already_absent` marker, and opportunistically
  clear the now-stale mapping.
- 404 on DELETE WITHOUT a mapping -> `absent` outcome with no
  mapping-invalidation call (nothing to invalidate).
- Group payload references the receiver's remote_ids for members.
- GitHub-kind SPs always POST groups (verb opt-out via the quirk
  `GROUP_UPDATE_VERB` flag).
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from services.scim import client as scim_client
from services.scim import worker


@contextmanager
def _worker_patches(db: MagicMock, **extra_patches: Any):
    """Patch every database/audit-log reference the worker dispatch touches.

    `extra_patches` mounts additional `mock.patch` paths as kwargs
    (`name=patch_object`) and yields a dict so tests can read back the
    underlying mocks for assertions.
    """
    with ExitStack() as stack:
        stack.enter_context(patch("services.scim.worker.database", db))
        stack.enter_context(patch("services.scim.sync_log.database", db))
        stack.enter_context(patch("services.scim.remote_ids.database", db))
        stack.enter_context(patch("services.scim.remote_ids.log_event", MagicMock()))
        mounted = {}
        for name, p in extra_patches.items():
            mounted[name] = stack.enter_context(p)
        yield mounted


def _entry(
    sp_id: str = "sp-1",
    resource_type: str = "user",
    resource_id: str = "user-1",
    attempts: int = 0,
) -> dict:
    return {
        "id": str(uuid4()),
        "sp_id": sp_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "attempts": attempts,
        "next_attempt_at": None,
        "last_error": None,
        "dead_letter_at": None,
    }


def _sp(sp_id: str = "sp-1", kind: str = "generic") -> dict:
    return {
        "id": sp_id,
        "name": "Test SP",
        "scim_enabled": True,
        "scim_target_url": "https://scim.example.com/scim/v2",
        "scim_kind": kind,
        "scim_membership_mode": "effective",
        "scim_log_retention": "3",
        "available_to_all": False,
    }


def _db(
    *,
    queue_entries: list[dict],
    sp: dict,
    user_with_email: dict | None = None,
    user_full: dict | None = None,
    scope_sps: list[dict] | None = None,
    group_row: dict | None = None,
    group_members: list[list[dict]] | None = None,
    remote_id_mapping: dict | None = None,
    member_remote_id_lookup: dict[str, str] | None = None,
) -> MagicMock:
    db = MagicMock()
    db.scim_push_queue.list_ready_entries.return_value = queue_entries
    db.service_providers.get_scim_target.return_value = sp
    db.user_emails.get_user_with_primary_email.return_value = user_with_email
    db.users.get_user_by_id.return_value = user_full
    db.scim_scope.scim_sps_granting_user.return_value = scope_sps or []
    db.groups.get_group_by_id.return_value = group_row
    db.groups.get_effective_members.side_effect = group_members or [[], []]
    db.scim_sync_log.create_entry.return_value = {"id": "log-1"}
    db.scim_remote_ids.get_one.return_value = remote_id_mapping
    db.scim_remote_ids.get_for_users.return_value = member_remote_id_lookup or {}
    db.scim_remote_ids.upsert.return_value = ({"remote_id": "captured"}, True)
    db.scim_remote_ids.delete.return_value = 1
    return db


@pytest.fixture
def fake_now() -> datetime:
    return datetime(2026, 5, 17, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# POST captures mapping on first push
# ---------------------------------------------------------------------------


def test_first_user_push_uses_post_and_captures_mapping(fake_now: datetime) -> None:
    """No mapping -> POST. Successful POST records the receiver's `id`."""
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1"}],
        remote_id_mapping=None,
    )
    success = scim_client.PushResult(
        status="success", http_status=201, reason=None, scim_id="ext-mint-1"
    )
    with _worker_patches(
        db,
        post=patch("services.scim.worker.scim_client.push_user", return_value=success),
        put=patch("services.scim.worker.scim_client.put_user"),
    ) as mocks:
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["succeeded"] == 1
    mocks["post"].assert_called_once()
    mocks["put"].assert_not_called()
    db.scim_remote_ids.upsert.assert_called_once()
    kwargs = db.scim_remote_ids.upsert.call_args.kwargs
    assert kwargs["weftid_id"] == "user-1"
    assert kwargs["remote_id"] == "ext-mint-1"
    assert kwargs["resource_type"] == "user"


def test_first_user_push_without_scim_id_does_not_record_mapping(fake_now: datetime) -> None:
    """POST success without an `id` in the response: no mapping recorded.

    Some SPs return 204 No Content or omit the id from the body. The
    worker should not synthesise a mapping from nothing -- the next push
    will POST again, and the SP either returns the id or 409s.
    """
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1"}],
        remote_id_mapping=None,
    )
    success = scim_client.PushResult(status="success", http_status=204, reason=None, scim_id=None)
    with _worker_patches(
        db,
        post=patch("services.scim.worker.scim_client.push_user", return_value=success),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["succeeded"] == 1
    db.scim_remote_ids.upsert.assert_not_called()


# ---------------------------------------------------------------------------
# PUT used on subsequent push
# ---------------------------------------------------------------------------


def test_subsequent_user_push_uses_put_with_remote_id(fake_now: datetime) -> None:
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1"}],
        remote_id_mapping={"id": "row-1", "remote_id": "ext-mint-1"},
    )
    success = scim_client.PushResult(
        status="success", http_status=200, reason=None, scim_id="ext-mint-1"
    )
    with _worker_patches(
        db,
        put=patch("services.scim.worker.scim_client.put_user", return_value=success),
        post=patch("services.scim.worker.scim_client.push_user"),
    ) as mocks:
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["succeeded"] == 1
    mocks["post"].assert_not_called()
    mocks["put"].assert_called_once()
    assert mocks["put"].call_args.args[1] == "ext-mint-1"


# ---------------------------------------------------------------------------
# DELETE uses remote_id when mapped, WeftID UUID when not
# ---------------------------------------------------------------------------


def test_delete_uses_remote_id_when_mapping_exists(fake_now: datetime) -> None:
    """User out of scope + mapping -> DELETE /Users/<remote_id>."""
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[],
        remote_id_mapping={"id": "row-1", "remote_id": "ext-mint-1"},
    )
    success = scim_client.PushResult(status="success", http_status=204, reason=None, scim_id=None)
    with _worker_patches(
        db,
        delete=patch("services.scim.worker.scim_client.delete_user", return_value=success),
    ) as mocks:
        worker.process_pending_pushes("tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok")
    mocks["delete"].assert_called_once()
    assert mocks["delete"].call_args.args[1] == "ext-mint-1"


def test_delete_falls_back_to_weftid_uuid_without_mapping(fake_now: datetime) -> None:
    """No mapping -> DELETE /Users/<weftid_uuid>. Backwards-compat for
    pre-mapping rows; receivers that key on externalId still work."""
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[],
        remote_id_mapping=None,
    )
    success = scim_client.PushResult(status="success", http_status=204, reason=None, scim_id=None)
    with _worker_patches(
        db,
        delete=patch("services.scim.worker.scim_client.delete_user", return_value=success),
    ) as mocks:
        worker.process_pending_pushes("tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok")
    assert mocks["delete"].call_args.args[1] == "user-1"


# ---------------------------------------------------------------------------
# 404 invalidation
# ---------------------------------------------------------------------------


def test_404_on_put_invalidates_mapping_and_reclassifies_as_retryable(
    fake_now: datetime,
) -> None:
    """The mapping is stale: receiver no longer recognises the remote_id.

    The worker invalidates the mapping (so the next pass POSTs) and
    reclassifies the outcome as retryable. The queue row remains; the
    sync_log row is marked failed (retry pending) with a specific
    reason. This is the heart of the iteration's correctness story:
    a single 404 fix-up reconnects the resource on the next attempt
    without operator intervention.
    """
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1"}],
        remote_id_mapping={"id": "row-1", "remote_id": "stale-id"},
    )
    put_404 = scim_client.PushResult(
        status="permanent",
        http_status=404,
        reason="client_error (HTTP 404)",
        scim_id=None,
    )
    with _worker_patches(
        db,
        put=patch("services.scim.worker.scim_client.put_user", return_value=put_404),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["retried"] == 1
    assert result["dead_lettered"] == 0
    db.scim_remote_ids.delete.assert_called_once_with("tenant-1", "sp-1", "user", "user-1")
    update_kwargs = db.scim_sync_log.update_status.call_args.kwargs
    assert update_kwargs["status"] == "failed"
    assert "remote_id_invalidated" in update_kwargs["error"]


def test_404_on_delete_with_mapping_is_absent_and_clears_mapping(
    fake_now: datetime,
) -> None:
    """DELETE 404 with a known mapping: the resource is genuinely gone.

    Treated as `absent` (success-like): queue row drained, sync_log
    marked done with the `already_absent` marker. The mapping is also
    cleared opportunistically -- it pointed at a resource that no
    longer exists, so any future POST gets a fresh mapping.
    """
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email=None,  # user is gone -> worker emits DELETE
        remote_id_mapping={"id": "row-1", "remote_id": "ext-1"},
    )
    delete_404_absent = scim_client.PushResult(
        status="absent",
        http_status=404,
        reason="already_absent (HTTP 404 on DELETE)",
        scim_id=None,
    )
    with _worker_patches(
        db,
        delete=patch(
            "services.scim.worker.scim_client.delete_user",
            return_value=delete_404_absent,
        ),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["absent"] == 1
    db.scim_push_queue.delete_entry.assert_called_once_with("tenant-1", entry["id"])
    update_kwargs = db.scim_sync_log.update_status.call_args.kwargs
    assert update_kwargs["status"] == "done"
    assert update_kwargs["error"].startswith("already_absent")
    db.scim_remote_ids.delete.assert_called_once_with("tenant-1", "sp-1", "user", "user-1")


def test_404_on_delete_without_mapping_is_absent_no_invalidation(
    fake_now: datetime,
) -> None:
    """DELETE 404 with no mapping: nothing to invalidate. Still `absent`."""
    entry = _entry()
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        user_with_email=None,
        remote_id_mapping=None,
    )
    delete_404 = scim_client.PushResult(
        status="absent",
        http_status=404,
        reason="already_absent (HTTP 404 on DELETE)",
        scim_id=None,
    )
    with _worker_patches(
        db,
        delete=patch("services.scim.worker.scim_client.delete_user", return_value=delete_404),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["absent"] == 1
    db.scim_push_queue.delete_entry.assert_called_once_with("tenant-1", entry["id"])
    db.scim_remote_ids.delete.assert_not_called()


# ---------------------------------------------------------------------------
# Group dispatch resolves member remote_ids
# ---------------------------------------------------------------------------


def test_group_push_passes_member_remote_ids_to_payload_builder(
    fake_now: datetime,
) -> None:
    """The worker batch-fetches `get_for_users` for the group's members
    and the resulting Group resource references the receiver's ids."""
    entry = _entry(resource_type="group", resource_id="g-1")
    members = [
        {"user_id": "user-a", "is_direct": True, "email": "a@ex.com", "first_name": "A"},
        {"user_id": "user-b", "is_direct": True, "email": "b@ex.com", "first_name": "B"},
    ]
    db = _db(
        queue_entries=[entry],
        sp=_sp(),
        group_row={"id": "g-1", "name": "Engineers"},
        group_members=[members, []],
        member_remote_id_lookup={"user-a": "ra", "user-b": "rb"},
    )
    success = scim_client.PushResult(
        status="success", http_status=201, reason=None, scim_id="g-ext"
    )
    with _worker_patches(
        db,
        post=patch("services.scim.worker.scim_client.push_group", return_value=success),
    ) as mocks:
        worker.process_pending_pushes("tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok")
    sent = mocks["post"].call_args.args[1]
    assert [m["value"] for m in sent["members"]] == ["ra", "rb"]
    fetch_kwargs = db.scim_remote_ids.get_for_users.call_args
    assert fetch_kwargs.args[0] == "tenant-1"
    assert fetch_kwargs.args[1] == "sp-1"
    assert set(fetch_kwargs.args[2]) == {"user-a", "user-b"}


def test_github_kind_sp_always_posts_groups_even_with_mapping(fake_now: datetime) -> None:
    """GitHub returns 405 on PUT /Groups/<id>; the quirk opts out of PUT
    via `GROUP_UPDATE_VERB = "POST"`. Verify the worker honours it: even
    with a recorded mapping, the dispatch path stays on POST."""
    entry = _entry(resource_type="group", resource_id="g-1")
    db = _db(
        queue_entries=[entry],
        sp=_sp(kind="github"),
        group_row={"id": "g-1", "name": "Engineers"},
        group_members=[[], []],
        remote_id_mapping={"id": "row-1", "remote_id": "gh-grp-1"},
    )
    success = scim_client.PushResult(
        status="success", http_status=201, reason=None, scim_id="gh-grp-1"
    )
    with _worker_patches(
        db,
        post=patch("services.scim.worker.scim_client.push_group", return_value=success),
        put=patch("services.scim.worker.scim_client.put_group"),
    ) as mocks:
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["succeeded"] == 1
    mocks["post"].assert_called_once()
    mocks["put"].assert_not_called()
