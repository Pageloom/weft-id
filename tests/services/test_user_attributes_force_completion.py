"""Tests for the Iteration 7 required-field enforcement helpers.

Covers:
* ``compute_missing_required`` -- the per-user "what required keys are
  missing" computation, including the locked vs unlocked split.
* ``list_users_with_missing_required`` -- the admin Todo data source
  (one DB round trip; no N+1).
* ``bulk_set_force_profile_completion`` -- the admin bulk action,
  including the lock-skip rule and the per-user event log entry.
* ``set_user_attribute`` auto-clear of ``force_profile_completion`` --
  once a user fills all required+unlocked attributes the gate releases.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
import pytest
from services.exceptions import ForbiddenError
from services.types import RequestingUser
from services.users.attributes import (
    bulk_set_force_profile_completion,
    compute_missing_required,
    list_users_with_missing_required,
    set_user_attribute,
)

# ---------------------------------------------------------------------------
# Helpers (mirror test_user_attributes_service patterns)
# ---------------------------------------------------------------------------


def _seed_config(
    tenant_id,
    *,
    key: str,
    enabled: bool = True,
    required: bool = False,
    mirror_from_idp: bool = False,
    locked_for_users: bool = False,
    send_to_sps_default: bool = True,
):
    from constants.user_attributes import ATTRIBUTES_BY_KEY

    attr = ATTRIBUTES_BY_KEY[key]
    database.execute(
        tenant_id,
        """
        INSERT INTO tenant_attribute_config (
            tenant_id, attribute_key, category, enabled, required,
            mirror_from_idp, locked_for_users, send_to_sps_default
        ) VALUES (
            :tenant_id, :attribute_key, :category, :enabled, :required,
            :mirror_from_idp, :locked_for_users, :send_to_sps_default
        )
        ON CONFLICT (tenant_id, attribute_key) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            required = EXCLUDED.required,
            mirror_from_idp = EXCLUDED.mirror_from_idp,
            locked_for_users = EXCLUDED.locked_for_users,
            send_to_sps_default = EXCLUDED.send_to_sps_default
        """,
        {
            "tenant_id": str(tenant_id),
            "attribute_key": key,
            "category": attr.category,
            "enabled": enabled,
            "required": required,
            "mirror_from_idp": mirror_from_idp,
            "locked_for_users": locked_for_users,
            "send_to_sps_default": send_to_sps_default,
        },
    )


def _admin_requester(tenant_id, user_id=None) -> RequestingUser:
    return RequestingUser(
        id=str(user_id or uuid4()),
        tenant_id=str(tenant_id),
        role="admin",
    )


def _member_requester(test_user) -> RequestingUser:
    return RequestingUser(
        id=str(test_user["id"]),
        tenant_id=str(test_user["tenant_id"]),
        role="member",
    )


# ---------------------------------------------------------------------------
# compute_missing_required
# ---------------------------------------------------------------------------


def test_compute_missing_required_returns_empty_when_no_required_keys(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=False)
    missing = compute_missing_required(test_user["tenant_id"], str(test_user["id"]))
    assert missing == []


def test_compute_missing_required_lists_missing_unlocked_keys(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    _seed_config(test_user["tenant_id"], key="department", required=True)
    missing = compute_missing_required(test_user["tenant_id"], str(test_user["id"]))
    keys = {key for key, _locked in missing}
    assert keys == {"job_title", "department"}
    assert all(locked is False for _key, locked in missing)


def test_compute_missing_required_flags_locked_correctly(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True, locked_for_users=True)
    _seed_config(test_user["tenant_id"], key="department", required=True)
    missing = compute_missing_required(test_user["tenant_id"], str(test_user["id"]))
    lookup = dict(missing)
    assert lookup["job_title"] is True
    assert lookup["department"] is False


def test_compute_missing_required_excludes_present_values(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    missing = compute_missing_required(test_user["tenant_id"], str(test_user["id"]))
    assert missing == []


def test_compute_missing_required_ignores_disabled_rows(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True, enabled=False)
    missing = compute_missing_required(test_user["tenant_id"], str(test_user["id"]))
    assert missing == []


def test_compute_missing_required_treats_whitespace_as_missing(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    # Upsert a whitespace value directly via DB so we can test the filter
    # without tripping the service-layer empty-value rejection.
    database.execute(
        test_user["tenant_id"],
        """
        INSERT INTO user_attributes (tenant_id, user_id, attribute_key, value)
        VALUES (:tenant_id, :user_id, :key, '   ')
        ON CONFLICT (user_id, attribute_key) DO UPDATE SET value = EXCLUDED.value
        """,
        {
            "tenant_id": str(test_user["tenant_id"]),
            "user_id": test_user["id"],
            "key": "job_title",
        },
    )
    missing = compute_missing_required(test_user["tenant_id"], str(test_user["id"]))
    assert [key for key, _locked in missing] == ["job_title"]


# ---------------------------------------------------------------------------
# list_users_with_missing_required (admin Todo data source)
# ---------------------------------------------------------------------------


def test_list_users_with_missing_required_requires_admin(test_user):
    member = _member_requester(test_user)
    with pytest.raises(ForbiddenError):
        list_users_with_missing_required(member)


def test_list_users_with_missing_required_returns_rows(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    _seed_config(test_user["tenant_id"], key="department", required=True, locked_for_users=True)
    admin = _admin_requester(test_user["tenant_id"])
    rows = list_users_with_missing_required(admin)
    user_rows = [r for r in rows if str(r["user_id"]) == str(test_user["id"])]
    keys = {r["attribute_key"] for r in user_rows}
    assert keys == {"job_title", "department"}
    locked_lookup = {r["attribute_key"]: r["locked"] for r in user_rows}
    assert locked_lookup == {"job_title": False, "department": True}


def test_list_users_with_missing_required_excludes_users_with_complete_profile(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    admin = _admin_requester(test_user["tenant_id"])
    rows = list_users_with_missing_required(admin)
    assert all(str(r["user_id"]) != str(test_user["id"]) for r in rows)


def test_list_users_with_missing_required_includes_force_flag(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    database.users.set_force_profile_completion(test_user["tenant_id"], str(test_user["id"]), True)
    admin = _admin_requester(test_user["tenant_id"])
    rows = list_users_with_missing_required(admin)
    matched = [r for r in rows if str(r["user_id"]) == str(test_user["id"])]
    assert matched
    assert all(r["force_profile_completion"] is True for r in matched)


# ---------------------------------------------------------------------------
# bulk_set_force_profile_completion
# ---------------------------------------------------------------------------


def test_bulk_set_force_profile_completion_requires_admin(test_user):
    member = _member_requester(test_user)
    with pytest.raises(ForbiddenError):
        bulk_set_force_profile_completion(member, [str(test_user["id"])])


def test_bulk_set_force_profile_completion_flags_user_with_unlocked_missing(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    admin = _admin_requester(test_user["tenant_id"])
    result = bulk_set_force_profile_completion(admin, [str(test_user["id"])])
    assert result["flagged"] == [str(test_user["id"])]
    assert result["skipped_locked"] == []
    assert result["skipped_complete"] == []
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["force_profile_completion"] is True


def test_bulk_set_force_profile_completion_skips_user_with_only_locked_missing(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True, locked_for_users=True)
    admin = _admin_requester(test_user["tenant_id"])
    result = bulk_set_force_profile_completion(admin, [str(test_user["id"])])
    assert result["flagged"] == []
    assert result["skipped_locked"] == [str(test_user["id"])]
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["force_profile_completion"] is False


def test_bulk_set_force_profile_completion_skips_user_with_no_missing(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    admin = _admin_requester(test_user["tenant_id"])
    result = bulk_set_force_profile_completion(admin, [str(test_user["id"])])
    assert result["flagged"] == []
    assert result["skipped_complete"] == [str(test_user["id"])]


def test_bulk_set_force_profile_completion_emits_event_per_flagged_user(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    admin = _admin_requester(test_user["tenant_id"])
    with patch("services.users.attributes.log_event") as mock_log:
        bulk_set_force_profile_completion(admin, [str(test_user["id"])])
    assert mock_log.call_count == 1
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "user_force_profile_completion_set"
    assert call_kwargs["artifact_id"] == str(test_user["id"])
    assert "missing_keys" in call_kwargs["metadata"]


def test_bulk_set_force_profile_completion_with_mixed_users_splits_results(test_user, test_tenant):
    """Two users, one unlocked-missing, one locked-only-missing."""
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    _seed_config(test_user["tenant_id"], key="department", required=True, locked_for_users=True)

    # Second user with only the locked-required missing.
    second = database.fetchone(
        test_tenant["id"],
        """
        INSERT INTO users (tenant_id, first_name, last_name, role)
        VALUES (:tenant_id, 'Second', 'Person', 'member') RETURNING id
        """,
        {"tenant_id": test_tenant["id"]},
    )
    # Give second user the unlocked required value so only the locked one is missing.
    database.user_attributes.upsert_attribute(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        user_id=second["id"],
        attribute_key="job_title",
        value="Engineer",
    )

    admin = _admin_requester(test_user["tenant_id"])
    result = bulk_set_force_profile_completion(admin, [str(test_user["id"]), str(second["id"])])
    assert str(test_user["id"]) in result["skipped_locked"]
    assert str(second["id"]) in result["skipped_locked"]
    assert result["flagged"] == []


def test_bulk_set_force_profile_completion_preflight_one_round_trip(test_user, test_tenant):
    """Nit 11: the preflight existence check uses ONE round-trip via ANY(:ids),
    not one SELECT per user.

    The previous implementation looped and issued ``N`` ``SELECT id FROM users
    WHERE id = :id`` statements. With even a few hundred candidate users that
    turns into a noticeable latency spike on every admin bulk action. The
    set-based form (``WHERE id = ANY(:ids)``) is one query regardless of
    ``len(user_ids)``.

    Verification: wrap ``database.session`` so we observe every cursor
    ``execute()`` call without mutating the cursor's read-only attributes,
    and count the statements that start with ``select id from users``. The
    preflight is the only call site for that exact statement on this path,
    so the count IS the round-trip count for the existence check.
    """
    _seed_config(test_user["tenant_id"], key="job_title", required=True)

    # Three valid users in the same tenant so the preflight has multiple
    # ids to check. If the implementation backslides to a per-user loop,
    # this will record 3 SELECT statements instead of 1.
    extra_user_ids = [str(test_user["id"])]
    for nth in range(2):
        row = database.fetchone(
            test_tenant["id"],
            """
            INSERT INTO users (tenant_id, first_name, last_name, role)
            VALUES (:tenant_id, :first_name, 'Bulk', 'member') RETURNING id
            """,
            {"tenant_id": test_tenant["id"], "first_name": f"Bulk{nth}"},
        )
        extra_user_ids.append(str(row["id"]))

    select_users_count = 0
    real_session = database.session

    from contextlib import contextmanager

    class _CursorSpy:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, query, params=None):
            nonlocal select_users_count
            if isinstance(query, str):
                normalized = " ".join(query.lower().split())
                if normalized.startswith("select id from users"):
                    select_users_count += 1
            if params is None:
                return self._inner.execute(query)
            return self._inner.execute(query, params)

        def fetchall(self):
            return self._inner.fetchall()

        def fetchone(self):
            return self._inner.fetchone()

        @property
        def rowcount(self):
            return self._inner.rowcount

        def __iter__(self):
            return iter(self._inner)

    @contextmanager
    def _spy_session(*args, **kwargs):
        with real_session(*args, **kwargs) as cur:
            yield _CursorSpy(cur)

    admin = _admin_requester(test_user["tenant_id"])

    with patch("database._core.session", _spy_session):
        result = bulk_set_force_profile_completion(admin, extra_user_ids)

    # One preflight SELECT regardless of N candidates.
    assert select_users_count == 1, (
        f"expected exactly 1 preflight SELECT for {len(extra_user_ids)} ids, "
        f"got {select_users_count}"
    )

    # Sanity: the call still functions correctly (test_user has the missing
    # required key; the two new users have no email/missing-row history but
    # are still real users in the tenant, so the preflight doesn't 404).
    # We don't assert on the exact contents of flagged/skipped here -- the
    # other tests pin behaviour. The point is the round-trip count.
    assert isinstance(result, dict)
    assert "flagged" in result
    assert "skipped_locked" in result
    assert "skipped_complete" in result


def test_bulk_set_force_profile_completion_empty_user_ids_short_circuits(test_user):
    """Nit 11: an empty ``user_ids`` list must NOT issue the preflight SELECT.

    psycopg cannot infer the element type of an empty ``ARRAY[]`` literal and
    chokes with ``cannot determine type of empty array``. Without the
    ``if user_ids:`` guard, the bulk helper would raise a database-level error
    on a no-op call.

    Verification: spy the cursor and assert ZERO ``select id from users``
    statements are issued; the function returns the expected empty result;
    no exception is raised.
    """
    _seed_config(test_user["tenant_id"], key="job_title", required=True)

    select_users_count = 0
    real_session = database.session

    from contextlib import contextmanager

    class _CursorSpy:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, query, params=None):
            nonlocal select_users_count
            if isinstance(query, str):
                normalized = " ".join(query.lower().split())
                if normalized.startswith("select id from users"):
                    select_users_count += 1
            if params is None:
                return self._inner.execute(query)
            return self._inner.execute(query, params)

        def fetchall(self):
            return self._inner.fetchall()

        def fetchone(self):
            return self._inner.fetchone()

        @property
        def rowcount(self):
            return self._inner.rowcount

        def __iter__(self):
            return iter(self._inner)

    @contextmanager
    def _spy_session(*args, **kwargs):
        with real_session(*args, **kwargs) as cur:
            yield _CursorSpy(cur)

    admin = _admin_requester(test_user["tenant_id"])

    with patch("database._core.session", _spy_session):
        result = bulk_set_force_profile_completion(admin, [])

    assert select_users_count == 0, (
        f"empty user_ids must not issue a preflight SELECT, got {select_users_count}"
    )
    assert result == {"flagged": [], "skipped_locked": [], "skipped_complete": []}


def test_bulk_set_force_profile_completion_rejects_unknown_user_ids(test_user):
    """A user_id that does not belong to the tenant raises NotFoundError.

    Without the pre-flight check, RLS would silently classify the foreign
    UUID as ``skipped_complete`` and the audit log would record an
    artifact_id from outside the actor's tenant.
    """
    from services.exceptions import NotFoundError

    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    admin = _admin_requester(test_user["tenant_id"])

    bogus = str(uuid4())
    with pytest.raises(NotFoundError) as exc_info:
        bulk_set_force_profile_completion(admin, [str(test_user["id"]), bogus])
    assert bogus in str(exc_info.value)

    # Confirm the real user was NOT flagged (atomic-all-or-nothing).
    refreshed = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert refreshed["force_profile_completion"] is False


# ---------------------------------------------------------------------------
# set_user_attribute auto-clears force_profile_completion
# ---------------------------------------------------------------------------


def test_set_user_attribute_clears_force_flag_when_all_unlocked_filled(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    database.users.set_force_profile_completion(test_user["tenant_id"], str(test_user["id"]), True)

    member = _member_requester(test_user)
    set_user_attribute(member, str(test_user["id"]), "job_title", "Engineer")

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["force_profile_completion"] is False


def test_set_user_attribute_keeps_force_flag_when_unlocked_still_missing(test_user):
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    _seed_config(test_user["tenant_id"], key="department", required=True)
    database.users.set_force_profile_completion(test_user["tenant_id"], str(test_user["id"]), True)

    member = _member_requester(test_user)
    set_user_attribute(member, str(test_user["id"]), "job_title", "Engineer")

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["force_profile_completion"] is True


def test_set_user_attribute_clears_force_flag_ignoring_locked_missing(test_user):
    """Locked-missing required values do NOT block the gate from clearing."""
    _seed_config(test_user["tenant_id"], key="job_title", required=True)
    _seed_config(test_user["tenant_id"], key="department", required=True, locked_for_users=True)
    database.users.set_force_profile_completion(test_user["tenant_id"], str(test_user["id"]), True)

    member = _member_requester(test_user)
    set_user_attribute(member, str(test_user["id"]), "job_title", "Engineer")

    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    # job_title is filled; department is locked and missing but doesn't matter
    # for the user-fixable gate.
    assert user["force_profile_completion"] is False
