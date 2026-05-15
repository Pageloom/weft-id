"""Tests for ``apply_attribute_form_updates`` (the bulk form helper).

The helper is the de-duplicated home of the bulk-set-attribute loop that
both ``app/routers/account.py`` (self-service) and
``app/routers/users/detail.py`` (admin) used to inline. It composes
``set_user_attribute`` / ``clear_user_attribute`` calls per submitted
form field and reports per-key results so the routers can pick a
redirect target.
"""

from __future__ import annotations

from uuid import uuid4

import database
from services.types import RequestingUser
from services.users.attributes import apply_attribute_form_updates

# ---------------------------------------------------------------------------
# Helpers (mirrors test_user_attributes_service.py)
# ---------------------------------------------------------------------------


def _seed_config(
    tenant_id,
    *,
    enabled: bool = True,
    locked_for_users: bool = False,
    keys=("job_title", "department", "city"),
):
    from constants.user_attributes import ATTRIBUTES_BY_KEY

    for key in keys:
        attr = ATTRIBUTES_BY_KEY[key]
        database.execute(
            tenant_id,
            """
            INSERT INTO tenant_attribute_config (
                tenant_id, attribute_key, category, enabled, required,
                mirror_from_idp, locked_for_users, send_to_sps_default
            ) VALUES (
                :tenant_id, :attribute_key, :category, :enabled, false,
                false, :locked_for_users, true
            )
            ON CONFLICT (tenant_id, attribute_key) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                locked_for_users = EXCLUDED.locked_for_users
            """,
            {
                "tenant_id": str(tenant_id),
                "attribute_key": key,
                "category": attr.category,
                "enabled": enabled,
                "locked_for_users": locked_for_users,
            },
        )


def _make_requester(test_user, role: str = "member") -> RequestingUser:
    return RequestingUser(
        id=str(test_user["id"]),
        tenant_id=str(test_user["tenant_id"]),
        role=role,
    )


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


def test_apply_attribute_form_updates_all_clear_success(test_user):
    """Every key is valid and a value is written -- error_code stays None."""
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer", "department": "Platform", "city": "Berlin"},
        enforce_user_lock=True,
    )

    assert result["error_code"] is None
    assert set(result["set_keys"]) == {"job_title", "department", "city"}
    assert result["cleared_keys"] == []
    assert result["skipped_locked_keys"] == []

    # All three values landed in the canonical store.
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], str(test_user["id"]))
    by_key = {r["attribute_key"]: r["value"] for r in rows}
    assert by_key == {"job_title": "Engineer", "department": "Platform", "city": "Berlin"}


def test_apply_attribute_form_updates_empty_string_clears(test_user):
    """Empty / whitespace values trigger clear_user_attribute on existing rows."""
    _seed_config(test_user["tenant_id"])
    # Pre-seed a row to clear.
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "", "department": "   "},  # whitespace counts as clear
        enforce_user_lock=True,
    )

    assert result["error_code"] is None
    assert result["set_keys"] == []
    assert set(result["cleared_keys"]) == {"job_title", "department"}

    # Cleared row is gone.
    assert (
        database.user_attributes.get_attribute(
            test_user["tenant_id"], str(test_user["id"]), "job_title"
        )
        is None
    )


def test_apply_attribute_form_updates_only_submitted_keys_are_touched(test_user):
    """Keys not in form_data are left alone, even if enabled."""
    _seed_config(test_user["tenant_id"])
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="department",
        value="OldDept",
    )
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer"},
        enforce_user_lock=True,
    )

    assert result["error_code"] is None
    assert result["set_keys"] == ["job_title"]
    # department was NOT submitted -> untouched.
    dept = database.user_attributes.get_attribute(
        test_user["tenant_id"], str(test_user["id"]), "department"
    )
    assert dept and dept["value"] == "OldDept"


# ---------------------------------------------------------------------------
# Partial-failure path
# ---------------------------------------------------------------------------


def test_apply_attribute_form_updates_partial_validation_failure(test_user):
    """One key fails serialization; the rest still write; first error wins."""
    _seed_config(test_user["tenant_id"], keys=("job_title", "country"))
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {
            "job_title": "Engineer",
            "country": "not-a-real-country",  # fails 2-letter ISO check
        },
        enforce_user_lock=True,
    )

    # Invalid key produces ``invalid_<key>`` -- one of the two could win
    # depending on config-row iteration order; assert it's one of them.
    assert result["error_code"] == "invalid_country"
    # Valid key still wrote.
    assert "job_title" in result["set_keys"]
    row = database.user_attributes.get_attribute(
        test_user["tenant_id"], str(test_user["id"]), "job_title"
    )
    assert row and row["value"] == "Engineer"


def test_apply_attribute_form_updates_locked_skipped_for_users(test_user):
    """When enforce_user_lock=True, locked keys are skipped silently."""
    _seed_config(test_user["tenant_id"], locked_for_users=True)
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer", "department": "Platform"},
        enforce_user_lock=True,
    )

    # No write happened, no error -- the submitted keys were just skipped.
    # ``city`` was not in form_data, so it's not in skipped_locked_keys either.
    assert result["error_code"] is None
    assert result["set_keys"] == []
    assert set(result["skipped_locked_keys"]) == {"job_title", "department"}


def test_apply_attribute_form_updates_locked_writable_for_admin(test_user):
    """enforce_user_lock=False (admin path) lets locked keys through."""
    _seed_config(test_user["tenant_id"], locked_for_users=True)
    admin = RequestingUser(
        id=str(uuid4()),
        tenant_id=str(test_user["tenant_id"]),
        role="admin",
    )

    result = apply_attribute_form_updates(
        admin,
        str(test_user["id"]),
        {"job_title": "Engineer"},
        enforce_user_lock=False,
    )

    assert result["error_code"] is None
    assert result["set_keys"] == ["job_title"]
    assert result["skipped_locked_keys"] == []


def test_apply_attribute_form_updates_disabled_key_ignored(test_user):
    """Disabled config rows are skipped regardless of whether the form has them."""
    _seed_config(test_user["tenant_id"], enabled=False)
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer"},
        enforce_user_lock=True,
    )

    assert result["error_code"] is None
    assert result["set_keys"] == []
    assert result["cleared_keys"] == []


def test_apply_attribute_form_updates_unknown_key_in_form_is_ignored(test_user):
    """Submitting an unrecognized key just drops it; no rewrite path."""
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer", "nonexistent_attribute": "ignored"},
        enforce_user_lock=True,
    )

    assert result["error_code"] is None
    assert result["set_keys"] == ["job_title"]


def test_apply_attribute_form_updates_empty_form_is_noop(test_user):
    """Empty form_data returns the clean-empty result shape."""
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {},
        enforce_user_lock=True,
    )

    assert result == {
        "error_code": None,
        "set_keys": [],
        "cleared_keys": [],
        "skipped_locked_keys": [],
    }


def test_apply_attribute_form_updates_none_value_treated_as_clear(test_user):
    """A ``None`` value (rare but possible) clears the row."""
    _seed_config(test_user["tenant_id"])
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    requester = _make_requester(test_user, role="member")

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": None},
        enforce_user_lock=True,
    )

    assert result["error_code"] is None
    assert result["cleared_keys"] == ["job_title"]
    assert (
        database.user_attributes.get_attribute(
            test_user["tenant_id"], str(test_user["id"]), "job_title"
        )
        is None
    )


# ---------------------------------------------------------------------------
# Exception -> error_code mappings (per-key dispatch failures)
# ---------------------------------------------------------------------------


def test_apply_attribute_form_updates_not_found_maps_to_user_not_found(test_user, mocker):
    """``NotFoundError`` raised by the underlying writer surfaces as
    ``error_code='user_not_found'`` so the router can redirect to the list."""
    from services.exceptions import NotFoundError

    _seed_config(test_user["tenant_id"], keys=("job_title",))
    requester = _make_requester(test_user, role="member")

    mocker.patch(
        "services.users.attributes.set_user_attribute",
        side_effect=NotFoundError(message="user not found", code="user_not_found"),
    )

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer"},
        enforce_user_lock=True,
    )

    assert result["error_code"] == "user_not_found"
    assert result["set_keys"] == []
    assert result["cleared_keys"] == []


def test_apply_attribute_form_updates_generic_service_error_maps_to_save_failed(test_user, mocker):
    """A ``ServiceError`` that is neither ``NotFoundError`` nor
    ``ValidationError`` surfaces as the generic ``error_code='save_failed'``
    (rather than leaking the underlying cause to the user)."""
    from services.exceptions import ServiceError

    _seed_config(test_user["tenant_id"], keys=("job_title",))
    requester = _make_requester(test_user, role="member")

    mocker.patch(
        "services.users.attributes.set_user_attribute",
        side_effect=ServiceError(message="boom", code="something_else"),
    )

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer"},
        enforce_user_lock=True,
    )

    assert result["error_code"] == "save_failed"
    assert result["set_keys"] == []


def test_apply_attribute_form_updates_continues_after_per_key_failure(test_user, mocker):
    """The loop does NOT early-out after a per-key failure: a later valid
    key still writes. Pins the current "continue after error" semantics so
    a future refactor can't silently swap in an early-return."""
    from services.exceptions import ValidationError

    _seed_config(test_user["tenant_id"], keys=("job_title", "department"))
    requester = _make_requester(test_user, role="member")

    # First call (whichever key is iterated first) raises ValidationError;
    # the second call succeeds. We patch the underlying writer so we don't
    # depend on the registry's serializer for a stable "bad value".
    call_count = {"n": 0}

    def fake_set(_requester, _user_id, key, value):  # noqa: ARG001
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ValidationError(message=f"bad {key}", code=f"invalid_{key}")
        # Side-effect: write through to the real DB so the success assertion
        # below holds.
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key=key,
            value=value,
        )

    mocker.patch("services.users.attributes.set_user_attribute", side_effect=fake_set)

    result = apply_attribute_form_updates(
        requester,
        str(test_user["id"]),
        {"job_title": "Engineer", "department": "Platform"},
        enforce_user_lock=True,
    )

    # Two iterations happened (loop did not early-out).
    assert call_count["n"] == 2
    # First key (whichever it was) failed; the OTHER key was set.
    assert len(result["set_keys"]) == 1
    first_failed_key = result["error_code"].removeprefix("invalid_")
    assert result["error_code"] in {"invalid_job_title", "invalid_department"}
    # The successful key is the one that did NOT fail.
    succeeded_key = "department" if first_failed_key == "job_title" else "job_title"
    assert result["set_keys"] == [succeeded_key]


# ---------------------------------------------------------------------------
# Exported via the package facade
# ---------------------------------------------------------------------------


def test_helper_is_re_exported_from_services_users():
    """The router callers import via ``services.users.apply_attribute_form_updates``."""
    from services import users as users_service

    assert hasattr(users_service, "apply_attribute_form_updates")
    assert users_service.apply_attribute_form_updates is apply_attribute_form_updates


def test_attribute_view_builders_re_exported_from_services_users():
    """The three view builders relocated to ``services.users.attribute_views``
    are re-exported from the package facade so router imports of
    ``from services.users import build_idp_attribute_panel`` continue to
    resolve to the same callable."""
    from services import users as users_service
    from services.users import attribute_views

    for name in (
        "build_idp_attribute_panel",
        "build_attribute_groups_for_admin",
        "build_attribute_groups_for_self",
    ):
        assert hasattr(users_service, name), f"{name} not re-exported from services.users"
        assert getattr(users_service, name) is getattr(attribute_views, name), (
            f"{name} is not the same callable as services.users.attribute_views.{name}"
        )
