"""Unit tests for `services.scim.dispatch` trigger logic.

Database and queue are mocked here so we can assert each trigger's
fan-out shape (which `enqueue_*` calls it produces) without touching
Postgres. End-to-end coverage against a real schema lives in the
integration test module.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from constants.event_types import EVENT_TYPE_DESCRIPTIONS, EVENT_TYPE_SCIM_TRIGGERS
from services.scim import dispatch

# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------


def test_every_tagged_event_type_has_a_description() -> None:
    """The validation invariant: scim_trigger keys must be real events."""
    missing = sorted(set(EVENT_TYPE_SCIM_TRIGGERS) - set(EVENT_TYPE_DESCRIPTIONS))
    assert missing == [], f"scim_trigger references unknown event types: {missing}"


def test_every_tagged_trigger_name_resolves_to_a_callable() -> None:
    """Every trigger name in the registry must map to a function."""
    unknown = sorted(set(EVENT_TYPE_SCIM_TRIGGERS.values()) - set(dispatch._TRIGGERS.keys()))
    assert unknown == [], f"scim_trigger names with no function: {unknown}"


# ---------------------------------------------------------------------------
# scim_dispatch entry point
# ---------------------------------------------------------------------------


def test_scim_dispatch_no_op_for_untagged_event() -> None:
    """An event_type with no scim_trigger never touches the trigger funcs."""
    mock_trigger = MagicMock()
    with patch.dict(dispatch._TRIGGERS, {"enqueue_user_self": mock_trigger}):
        dispatch.scim_dispatch(
            event_type="login_failed",
            tenant_id="t",
            actor_user_id="a",
            artifact_type="user",
            artifact_id="u",
            metadata=None,
        )
    mock_trigger.assert_not_called()


def test_scim_dispatch_calls_matching_trigger() -> None:
    mock_trigger = MagicMock()
    with patch.dict(dispatch._TRIGGERS, {"enqueue_user_self": mock_trigger}):
        dispatch.scim_dispatch(
            event_type="user_created",
            tenant_id="t",
            actor_user_id="a",
            artifact_type="user",
            artifact_id="u",
            metadata={"role": "admin"},
        )
    mock_trigger.assert_called_once_with("t", "u", {"role": "admin"})


def test_scim_dispatch_swallows_trigger_exceptions(caplog: pytest.LogCaptureFixture) -> None:
    """A trigger that raises must not propagate to the caller."""

    def boom(*_a: Any, **_kw: Any) -> None:
        raise RuntimeError("trigger blew up")

    with patch.dict(dispatch._TRIGGERS, {"enqueue_user_self": boom}):
        # Must not raise.
        dispatch.scim_dispatch(
            event_type="user_created",
            tenant_id="t",
            actor_user_id="a",
            artifact_type="user",
            artifact_id="u",
            metadata=None,
        )

    assert any(
        "trigger blew up" in rec.getMessage() or "raised" in rec.getMessage()
        for rec in caplog.records
    )


def test_scim_dispatch_logs_unknown_trigger_name(caplog: pytest.LogCaptureFixture) -> None:
    with patch.dict(EVENT_TYPE_SCIM_TRIGGERS, {"user_created": "no_such_trigger"}, clear=False):
        dispatch.scim_dispatch(
            event_type="user_created",
            tenant_id="t",
            actor_user_id="a",
            artifact_type="user",
            artifact_id="u",
            metadata=None,
        )
    assert any("unknown trigger" in rec.getMessage() for rec in caplog.records)


# ---------------------------------------------------------------------------
# enqueue_user_self
# ---------------------------------------------------------------------------


def test_enqueue_user_self_fans_out_to_every_scim_sp() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_user.return_value = [
        {"id": "sp-a", "scim_membership_mode": "effective"},
        {"id": "sp-b", "scim_membership_mode": "direct"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_user_self("tenant-1", "user-1", {})

    db.scim_scope.scim_sps_granting_user.assert_called_once_with("tenant-1", "user-1")
    assert q.enqueue_user.call_count == 2
    q.enqueue_user.assert_any_call("tenant-1", "sp-a", "user-1")
    q.enqueue_user.assert_any_call("tenant-1", "sp-b", "user-1")


def test_enqueue_user_self_clean_noop_when_no_sps_in_scope() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_user.return_value = []
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_user_self("tenant-1", "user-1", {})

    q.enqueue_user.assert_not_called()


def test_enqueue_user_self_uses_metadata_pre_resolved_sps_when_present() -> None:
    """When `metadata["scim_pre_resolved_sps"]` is provided, the trigger
    must enqueue against those SP ids without re-querying the scope table.

    This is the path the hard-delete flow uses: the FK cascade on
    `group_memberships` wipes the user's group ties before the trigger
    runs, so the emitter resolves SP scope up front and stashes it on the
    event metadata.
    """
    db = MagicMock()
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_user_self(
            "tenant-1",
            "user-1",
            {"scim_pre_resolved_sps": ["sp-a", "sp-b"]},
        )

    # Scope lookup must be bypassed entirely.
    db.scim_scope.scim_sps_granting_user.assert_not_called()
    assert q.enqueue_user.call_count == 2
    q.enqueue_user.assert_any_call("tenant-1", "sp-a", "user-1")
    q.enqueue_user.assert_any_call("tenant-1", "sp-b", "user-1")


def test_enqueue_user_self_empty_pre_resolved_list_is_clean_noop() -> None:
    """An empty pre-resolved list is a deliberate "no SPs in scope" signal
    (e.g. the user had no SCIM-enabled SPs). It must NOT fall through to
    the scope query.
    """
    db = MagicMock()
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_user_self(
            "tenant-1",
            "user-1",
            {"scim_pre_resolved_sps": []},
        )

    db.scim_scope.scim_sps_granting_user.assert_not_called()
    q.enqueue_user.assert_not_called()


def test_enqueue_user_self_falls_through_to_query_when_no_metadata_hint() -> None:
    """When `scim_pre_resolved_sps` is absent, the trigger keeps the
    original behaviour of querying `scim_sps_granting_user`.
    """
    db = MagicMock()
    db.scim_scope.scim_sps_granting_user.return_value = [
        {"id": "sp-x", "scim_membership_mode": "effective"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_user_self("tenant-1", "user-1", {})

    db.scim_scope.scim_sps_granting_user.assert_called_once_with("tenant-1", "user-1")
    q.enqueue_user.assert_called_once_with("tenant-1", "sp-x", "user-1")


def test_enqueue_user_self_swallows_scope_lookup_errors() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_user.side_effect = RuntimeError("db down")
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        # Must not raise.
        dispatch.enqueue_user_self("tenant-1", "user-1", {})
    q.enqueue_user.assert_not_called()


# ---------------------------------------------------------------------------
# enqueue_group_self
# ---------------------------------------------------------------------------


def test_enqueue_group_self_pushes_group_resource_to_each_sp() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_via_group.return_value = [
        {"id": "sp-a", "scim_membership_mode": "effective"},
        {"id": "sp-b", "scim_membership_mode": "direct"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_group_self("tenant-1", "group-1", {})

    assert q.enqueue_group.call_count == 2
    q.enqueue_group.assert_any_call("tenant-1", "sp-a", "group-1")
    q.enqueue_group.assert_any_call("tenant-1", "sp-b", "group-1")
    q.enqueue_user.assert_not_called()


# ---------------------------------------------------------------------------
# enqueue_membership_change
# ---------------------------------------------------------------------------


def test_enqueue_membership_change_single_user_effective_mode() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_via_group.return_value = [
        {"id": "sp-a", "scim_membership_mode": "effective"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_membership_change("tenant-1", "group-1", {"user_id": "user-1"})

    q.enqueue_user.assert_called_once_with("tenant-1", "sp-a", "user-1")
    # Effective-mode SP does NOT get the group resource for a member change.
    q.enqueue_group.assert_not_called()


def test_enqueue_membership_change_direct_mode_also_pushes_group() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_via_group.return_value = [
        {"id": "sp-direct", "scim_membership_mode": "direct"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_membership_change("tenant-1", "group-1", {"user_id": "user-1"})

    q.enqueue_user.assert_called_once_with("tenant-1", "sp-direct", "user-1")
    q.enqueue_group.assert_called_once_with("tenant-1", "sp-direct", "group-1")


def test_enqueue_membership_change_bulk_user_ids() -> None:
    db = MagicMock()
    db.scim_scope.scim_sps_granting_via_group.return_value = [
        {"id": "sp-a", "scim_membership_mode": "effective"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_membership_change("tenant-1", "group-1", {"user_ids": ["u1", "u2", "u3"]})

    assert q.enqueue_user.call_count == 3
    q.enqueue_user.assert_any_call("tenant-1", "sp-a", "u1")
    q.enqueue_user.assert_any_call("tenant-1", "sp-a", "u2")
    q.enqueue_user.assert_any_call("tenant-1", "sp-a", "u3")


@pytest.mark.parametrize(
    ("event_type", "metadata"),
    [
        # `idp_group_member_added` from app/services/groups/idp.py (SAML auth sync)
        (
            "idp_group_member_added",
            {
                "idp_id": "idp-1",
                "idp_name": "Okta",
                "user_id": "user-1",
                "user_email": "u@example.com",
                "group_id": "group-1",
                "group_name": "Eng",
                "sync_source": "saml_authentication",
            },
        ),
        # `idp_group_member_removed` from app/services/groups/idp.py
        (
            "idp_group_member_removed",
            {
                "idp_id": "idp-1",
                "idp_name": "Okta",
                "user_id": "user-1",
                "user_email": "u@example.com",
                "group_id": "group-1",
                "group_name": "Eng",
                "sync_source": "saml_authentication",
            },
        ),
        # `idp_group_member_added` from `add_user_to_base_group` (no user_email)
        (
            "idp_group_member_added",
            {
                "idp_id": "idp-1",
                "idp_name": "Okta",
                "user_id": "user-1",
                "group_id": "group-1",
                "group_name": "Okta",
                "sync_source": "idp_assignment",
            },
        ),
        # `idp_group_member_removed` from `move_users_between_idps`
        (
            "idp_group_member_removed",
            {
                "idp_id": "old-idp",
                "idp_name": "OldOkta",
                "user_id": "user-1",
                "group_id": "group-1",
                "sync_source": "idp_reassignment",
            },
        ),
    ],
)
def test_enqueue_membership_change_handles_real_idp_event_metadata(
    event_type: str, metadata: dict[str, Any]
) -> None:
    """Lock in the contract between `app/services/groups/idp.py` (which
    emits `idp_group_member_added/removed`) and `enqueue_membership_change`.

    All call sites pass `metadata["user_id"]` (singular, string). Any drift
    to a different key (e.g. `idp_user_id`, `external_user_id`) would cause
    a silent dispatch drop; this test fails fast if that happens.

    Note: the event type itself is not used by the trigger function (it is
    matched in `EVENT_TYPE_SCIM_TRIGGERS` upstream). Parametrising the
    fixture here makes the call sites visible.
    """
    db = MagicMock()
    db.scim_scope.scim_sps_granting_via_group.return_value = [
        {"id": "sp-a", "scim_membership_mode": "effective"},
    ]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_membership_change("tenant-1", str(metadata["group_id"]), metadata)

    # The trigger MUST resolve scope and enqueue the user against the SP.
    db.scim_scope.scim_sps_granting_via_group.assert_called_once_with(
        "tenant-1", str(metadata["group_id"])
    )
    q.enqueue_user.assert_called_once_with("tenant-1", "sp-a", "user-1")


def test_enqueue_membership_change_missing_user_id_is_noop() -> None:
    db = MagicMock()
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_membership_change("tenant-1", "group-1", {})

    db.scim_scope.scim_sps_granting_via_group.assert_not_called()
    q.enqueue_user.assert_not_called()


# ---------------------------------------------------------------------------
# enqueue_grant_fan_out
# ---------------------------------------------------------------------------


def test_enqueue_grant_fan_out_skips_non_scim_sp() -> None:
    db = MagicMock()
    db.scim_scope.is_scim_enabled_sp.return_value = False
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_grant_fan_out("tenant-1", "sp-1", {"group_id": "g-1"})

    db.scim_scope.transitive_user_ids_for_group.assert_not_called()
    q.enqueue_user.assert_not_called()
    q.enqueue_group.assert_not_called()


def test_enqueue_grant_fan_out_single_group_fans_to_all_members() -> None:
    db = MagicMock()
    db.scim_scope.is_scim_enabled_sp.return_value = True
    db.scim_scope.transitive_user_ids_for_group.return_value = ["u1", "u2"]
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_grant_fan_out("tenant-1", "sp-1", {"group_id": "g-1"})

    assert q.enqueue_user.call_count == 2
    q.enqueue_user.assert_any_call("tenant-1", "sp-1", "u1")
    q.enqueue_user.assert_any_call("tenant-1", "sp-1", "u2")
    q.enqueue_group.assert_called_once_with("tenant-1", "sp-1", "g-1")


def test_enqueue_grant_fan_out_bulk_group_ids() -> None:
    db = MagicMock()
    db.scim_scope.is_scim_enabled_sp.return_value = True

    def members(_t: str, gid: str) -> list[str]:
        return {"g-1": ["u1"], "g-2": ["u1", "u2"]}[gid]

    db.scim_scope.transitive_user_ids_for_group.side_effect = members
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_grant_fan_out("tenant-1", "sp-1", {"group_ids": ["g-1", "g-2"]})

    # 1 user from g-1 + 2 from g-2 = 3 user enqueues, plus 2 group enqueues
    assert q.enqueue_user.call_count == 3
    assert q.enqueue_group.call_count == 2
    q.enqueue_group.assert_any_call("tenant-1", "sp-1", "g-1")
    q.enqueue_group.assert_any_call("tenant-1", "sp-1", "g-2")


def test_enqueue_grant_fan_out_missing_group_id_is_noop() -> None:
    db = MagicMock()
    q = MagicMock()
    with (
        patch("services.scim.dispatch.queue", q),
        patch.dict(__import__("sys").modules, {"database": db}),
    ):
        dispatch.enqueue_grant_fan_out("tenant-1", "sp-1", {})

    db.scim_scope.is_scim_enabled_sp.assert_not_called()
    q.enqueue_user.assert_not_called()
