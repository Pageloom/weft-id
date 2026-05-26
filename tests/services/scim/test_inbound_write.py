"""Tests for the inbound SCIM write service.

These mock the database layer and exercise the merge precedence, write
helpers, mutability gating, and event-log emission directly. Database
integration is exercised separately in `tests/database/test_scim_inbound_writes.py`.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from services.scim.inbound_write import (
    ScimWriteError,
    create_or_merge_user,
    patch_user,
    replace_user,
    soft_delete_user,
)


def _location_builder(uid: str) -> str:
    return f"https://t.test/scim/v2/inbound/i/Users/{uid}"


@pytest.fixture
def fake_session():
    """Return a context-manager session that yields a recording cursor."""
    cur = MagicMock()
    cur.fetchone.return_value = None

    session_cm = MagicMock()
    session_cm.__enter__.return_value = cur
    session_cm.__exit__.return_value = False

    return session_cm, cur


def _resolved_user(user_id: str) -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": "alice@x.test",
        "active": True,
        "meta": {
            "resourceType": "User",
            "location": _location_builder(user_id),
        },
    }


# ---------------------------------------------------------------------------
# create_or_merge_user
# ---------------------------------------------------------------------------


def test_create_path_creates_new_user_and_returns_201(fake_session):
    session_cm, cur = fake_session
    new_user_id = str(uuid4())
    cur.fetchone.return_value = None  # no externalId hit, no email hit

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write._create_user_from_scim", return_value=new_user_id
        ) as create_call,
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event") as log,
        patch(
            "services.scim.inbound_write.inbound_read.get_user",
            return_value=_resolved_user(new_user_id),
        ),
    ):
        payload, created = create_or_merge_user(
            "t",
            "i",
            {
                "userName": "alice@x.test",
                "externalId": "okta-1",
                "name": {"givenName": "Alice", "familyName": "Example"},
                "active": True,
            },
            location_builder=_location_builder,
        )
    assert created is True
    assert payload["id"] == new_user_id
    create_call.assert_called_once()
    event = log.call_args.kwargs
    assert event["event_type"] == "scim_user_received"
    assert event["metadata"]["merged"] is False
    assert event["metadata"]["external_id"] == "okta-1"


def test_merge_by_external_id_returns_existing_user(fake_session):
    session_cm, cur = fake_session
    existing_id = str(uuid4())
    # First fetchone (externalId lookup) hits.
    cur.fetchone.return_value = {"user_id": existing_id}

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": existing_id, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes") as writes,
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event") as log,
        patch(
            "services.scim.inbound_write.inbound_read.get_user",
            return_value=_resolved_user(existing_id),
        ),
    ):
        payload, created = create_or_merge_user(
            "t",
            "i",
            {"userName": "alice@x.test", "externalId": "okta-1"},
            location_builder=_location_builder,
        )
    assert created is False
    assert payload["id"] == existing_id
    # On merge we DO apply attribute writes but skip the names-overwrite.
    writes.assert_called_once()
    assert log.call_args.kwargs["metadata"]["merged"] is True


def test_merge_by_email_when_no_external_id_hit(fake_session):
    session_cm, cur = fake_session
    existing_id = str(uuid4())
    # First lookup (externalId) returns None, second (email) returns the hit.
    cur.fetchone.side_effect = [None, {"user_id": existing_id}]

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": existing_id, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user",
            return_value=_resolved_user(existing_id),
        ),
    ):
        _payload, created = create_or_merge_user(
            "t",
            "i",
            {
                "userName": "alice@x.test",
                "externalId": "okta-1",
                "emails": [{"value": "alice@x.test", "primary": True}],
            },
            location_builder=_location_builder,
        )
    assert created is False


def test_merge_rebinds_user_to_new_idp(fake_session):
    """A SCIM POST against IdP B for a user previously bound to IdP A
    must rebind their `saml_idp_id` so the read endpoints find them."""
    session_cm, cur = fake_session
    existing_id = str(uuid4())
    # No externalId in payload -> only email lookup runs.
    cur.fetchone.return_value = {"user_id": existing_id}

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": existing_id, "saml_idp_id": "old-idp"},
        ),
        patch("services.scim.inbound_write.database.saml.set_user_idp") as rebind,
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user",
            return_value=_resolved_user(existing_id),
        ),
    ):
        create_or_merge_user(
            "t",
            "new-idp",
            {
                "userName": "alice@x.test",
                "emails": [{"value": "alice@x.test", "primary": True}],
            },
            location_builder=_location_builder,
        )
    rebind.assert_called_once_with("t", existing_id, "new-idp")


def test_create_rejects_payload_missing_email(fake_session):
    session_cm, cur = fake_session
    cur.fetchone.return_value = None

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
    ):
        with pytest.raises(ScimWriteError) as exc:
            create_or_merge_user(
                "t",
                "i",
                {"name": {"givenName": "Alice"}},
                location_builder=_location_builder,
            )
    assert exc.value.status_code == 400
    assert exc.value.scim_type == "invalidValue"


def test_create_rejects_role_escalation(fake_session):
    session_cm, _cur = fake_session
    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
    ):
        with pytest.raises(ScimWriteError) as exc:
            create_or_merge_user(
                "t",
                "i",
                {"userName": "alice@x.test", "roles": ["admin"]},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "mutability"


def test_create_canonicalises_email_case():
    """The merge lookup must normalise the email before querying."""
    session_cm = MagicMock()
    cur = MagicMock()
    cur.fetchone.side_effect = [None, None]
    session_cm.__enter__.return_value = cur
    session_cm.__exit__.return_value = False

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write._create_user_from_scim", return_value=str(uuid4())
        ) as create_call,
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user("x")
        ),
    ):
        create_or_merge_user(
            "t",
            "i",
            {"userName": "Alice@Example.Test"},
            location_builder=_location_builder,
        )
    assert create_call.call_args.kwargs["canonical_email"] == "alice@example.test"


# ---------------------------------------------------------------------------
# replace_user
# ---------------------------------------------------------------------------


def test_replace_user_404_when_user_belongs_to_other_idp():
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": "u", "saml_idp_id": "other"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            replace_user("t", "i", "u", {"userName": "x"}, location_builder=_location_builder)
    assert exc.value.status_code == 404


def test_replace_user_triggers_deactivate_on_active_false():
    uid = str(uuid4())
    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={
                "id": uid,
                "saml_idp_id": "i",
                "is_inactivated": False,
                "first_name": "A",
                "last_name": "B",
            },
        ),
        patch("services.scim.inbound_write.database.users.update_user_profile"),
        patch("services.scim.inbound_write.apply_idp_attributes"),
        patch("services.scim.inbound_write._handle_active_transition") as transition,
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        replace_user(
            "t",
            "i",
            uid,
            {"userName": "x@y", "active": False, "name": {"givenName": "X", "familyName": "Y"}},
            location_builder=_location_builder,
        )
    assert transition.call_args.args[3] is False


def test_replace_user_rejects_role_in_body():
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            replace_user(
                "t",
                "i",
                uid,
                {"userName": "x", "role": "admin"},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "mutability"


# ---------------------------------------------------------------------------
# patch_user
# ---------------------------------------------------------------------------


def test_patch_simple_path_disable():
    uid = str(uuid4())
    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i", "is_inactivated": False},
        ),
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition") as transition,
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user(
            "t",
            "i",
            uid,
            {"Operations": [{"op": "replace", "path": "active", "value": False}]},
            location_builder=_location_builder,
        )
    assert transition.call_args.args[3] is False


def test_patch_batched_entra_style_ops():
    """Entra sends multi-op PATCH with URN-prefixed paths.

    All ops apply; the synthesised payload reflects every op.
    """
    uid = str(uuid4())
    body = {
        "Operations": [
            {"op": "Replace", "path": "displayName", "value": "New Name"},
            {"op": "Replace", "path": "name.givenName", "value": "New"},
            {
                "op": "Add",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                "value": "Bakery",
            },
        ]
    }
    captured_payload = {}

    def capture(_t, _i, _u, payload, **_k):
        captured_payload.update(payload)

    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes", side_effect=capture),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user("t", "i", uid, body, location_builder=_location_builder)
    from schemas.scim import ENTERPRISE_USER_SCHEMA

    assert captured_payload["displayName"] == "New Name"
    assert captured_payload["name"]["givenName"] == "New"
    assert captured_payload[ENTERPRISE_USER_SCHEMA]["department"] == "Bakery"


def test_patch_active_string_value_coerced_to_bool():
    """Entra sometimes sends `"value": "False"` (string). Coerce."""
    uid = str(uuid4())
    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i", "is_inactivated": False},
        ),
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition") as transition,
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user(
            "t",
            "i",
            uid,
            {"Operations": [{"op": "Replace", "path": "active", "value": "False"}]},
            location_builder=_location_builder,
        )
    assert transition.call_args.args[3] is False


def test_patch_rejects_forbidden_path():
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            patch_user(
                "t",
                "i",
                uid,
                {"Operations": [{"op": "replace", "path": "role", "value": "admin"}]},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "mutability"


def test_patch_rejects_bogus_path():
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            patch_user(
                "t",
                "i",
                uid,
                {"Operations": [{"op": "replace", "path": "garbage", "value": "x"}]},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "invalidPath"


def test_patch_empty_operations_rejected():
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError):
            patch_user("t", "i", uid, {"Operations": []}, location_builder=_location_builder)


def test_patch_no_path_replace_with_value_object():
    uid = str(uuid4())
    captured = {}

    def capture(_t, _i, _u, payload, **_k):
        captured.update(payload)

    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes", side_effect=capture),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user(
            "t",
            "i",
            uid,
            {"Operations": [{"op": "replace", "value": {"displayName": "Whole replace"}}]},
            location_builder=_location_builder,
        )
    assert captured["displayName"] == "Whole replace"


# ---------------------------------------------------------------------------
# soft_delete_user
# ---------------------------------------------------------------------------


def test_soft_delete_inactivates_and_logs_event():
    uid = str(uuid4())
    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i", "is_inactivated": False},
        ),
        patch(
            "services.scim.inbound_write.database.users.inactivate_user", return_value=1
        ) as inactivate,
        patch("services.scim.inbound_write.database.oauth2.revoke_all_user_tokens") as revoke,
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event") as log,
    ):
        soft_delete_user("t", "i", uid)
    inactivate.assert_called_once()
    revoke.assert_called_once()
    assert log.call_args.kwargs["event_type"] == "scim_user_deactivated"


def test_soft_delete_idempotent_when_already_inactivated():
    uid = str(uuid4())
    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i", "is_inactivated": True},
        ),
        patch("services.scim.inbound_write.database.users.inactivate_user") as inactivate,
        patch("services.scim.inbound_write.log_event") as log,
    ):
        soft_delete_user("t", "i", uid)
    inactivate.assert_not_called()
    log.assert_not_called()


def test_soft_delete_cross_idp_404():
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "other"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            soft_delete_user("t", "i", uid)
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# Vendor fixture round-trips
# ---------------------------------------------------------------------------


def test_okta_create_user_fixture_parses_cleanly(fake_session):
    from tests.fixtures.scim.inbound import load_fixture

    session_cm, cur = fake_session
    cur.fetchone.return_value = None
    new_id = str(uuid4())

    payload = load_fixture("okta", "create_user")

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write._create_user_from_scim", return_value=new_id
        ) as create_call,
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(new_id)
        ),
    ):
        _, created = create_or_merge_user("t", "i", payload, location_builder=_location_builder)
    assert created is True
    assert create_call.call_args.kwargs["external_id"] == "00u1okta12345xExAmpL"
    assert create_call.call_args.kwargs["first_name"] == "Alice"


def test_entra_create_user_fixture_parses_cleanly(fake_session):
    from tests.fixtures.scim.inbound import load_fixture

    session_cm, cur = fake_session
    cur.fetchone.return_value = None
    new_id = str(uuid4())

    payload = load_fixture("entra", "create_user")

    with (
        patch("services.scim.inbound_write.database.session", return_value=session_cm),
        patch(
            "services.scim.inbound_write._create_user_from_scim", return_value=new_id
        ) as create_call,
        patch("services.scim.inbound_write._apply_payload_writes"),
        patch("services.scim.inbound_write._handle_active_transition"),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(new_id)
        ),
    ):
        create_or_merge_user("t", "i", payload, location_builder=_location_builder)
    assert create_call.call_args.kwargs["external_id"] == "0c8a4f8e-1b2c-4d5e-9f8a-1a2b3c4d5e6f"


# ---------------------------------------------------------------------------
# Mutability gating (POST / PUT / PATCH) -- belt-and-braces for each path.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("forbidden_key", ["password", "mfa", "groups"])
def test_create_rejects_forbidden_top_level_attributes(forbidden_key, fake_session):
    """POST must reject password / mfa / groups outright with mutability."""
    session_cm, _cur = fake_session
    body = {"userName": "x@y.test", forbidden_key: "anything"}
    with patch("services.scim.inbound_write.database.session", return_value=session_cm):
        with pytest.raises(ScimWriteError) as exc:
            create_or_merge_user("t", "i", body, location_builder=_location_builder)
    assert exc.value.scim_type == "mutability"


@pytest.mark.parametrize("forbidden_key", ["password", "mfa_enabled"])
def test_replace_rejects_forbidden_top_level_attributes(forbidden_key):
    """PUT must reject the same set of forbidden keys."""
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            replace_user(
                "t",
                "i",
                uid,
                {"userName": "x", forbidden_key: True},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "mutability"


@pytest.mark.parametrize("forbidden_path", ["password", "mfa", "groups"])
def test_patch_rejects_forbidden_path_in_op(forbidden_path):
    """Each forbidden path on a PATCH op yields a mutability error."""
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            patch_user(
                "t",
                "i",
                uid,
                {"Operations": [{"op": "replace", "path": forbidden_path, "value": "x"}]},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "mutability"


def test_patch_rejects_forbidden_key_in_no_path_value_object():
    """A no-path PATCH with `value` containing a forbidden key must still reject."""
    uid = str(uuid4())
    with patch(
        "services.scim.inbound_write.database.users.get_user_by_id",
        return_value={"id": uid, "saml_idp_id": "i"},
    ):
        with pytest.raises(ScimWriteError) as exc:
            patch_user(
                "t",
                "i",
                uid,
                {"Operations": [{"op": "replace", "value": {"roles": ["admin"]}}]},
                location_builder=_location_builder,
            )
    assert exc.value.scim_type == "mutability"


# ---------------------------------------------------------------------------
# PATCH path normalisation: Okta `emails[type eq "work"].value` style filter
# strips down to `emails`; exotic / unsupported sub-attributes never raise 500.
# ---------------------------------------------------------------------------


def test_patch_okta_style_filtered_emails_path_normalises_to_emails():
    """Okta sends `emails[type eq "work"].value` as a PATCH path. We accept
    it by stripping the filter and treating the whole `emails` array as
    the target. The op's value (a scalar email string in this style) is
    wrapped into a single-entry emails array by `_patch_assign`."""
    uid = str(uuid4())
    captured = {}

    def capture(_t, _i, _u, payload, **_k):
        captured.update(payload)

    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes", side_effect=capture),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user(
            "t",
            "i",
            uid,
            {
                "Operations": [
                    {
                        "op": "replace",
                        "path": 'emails[type eq "work"].value',
                        "value": "work-only@x.test",
                    }
                ]
            },
            location_builder=_location_builder,
        )
    # Filter was stripped to `emails`; scalar wrapped to a list.
    assert captured["emails"] == [{"value": "work-only@x.test", "primary": True}]


def test_patch_remove_emails_clears_to_empty_list():
    """`remove` on `emails` produces an empty array, not a 500."""
    uid = str(uuid4())
    captured = {}

    def capture(_t, _i, _u, payload, **_k):
        captured.update(payload)

    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes", side_effect=capture),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user(
            "t",
            "i",
            uid,
            {"Operations": [{"op": "remove", "path": "emails"}]},
            location_builder=_location_builder,
        )
    assert captured["emails"] == []


def test_entra_batched_patch_fixture(fake_session):
    """Entra batched PATCH: replace displayName + name.givenName + add department."""
    from tests.fixtures.scim.inbound import load_fixture

    uid = str(uuid4())
    fixture = load_fixture("entra", "patch_user_batched")
    captured = {}

    def capture(_t, _i, _u, payload, **_k):
        captured.update(payload)

    with (
        patch(
            "services.scim.inbound_write.database.users.get_user_by_id",
            return_value={"id": uid, "saml_idp_id": "i"},
        ),
        patch("services.scim.inbound_write._apply_payload_writes", side_effect=capture),
        patch("services.scim.inbound_write._bump_updated_at"),
        patch("services.scim.inbound_write.log_event"),
        patch(
            "services.scim.inbound_write.inbound_read.get_user", return_value=_resolved_user(uid)
        ),
    ):
        patch_user("t", "i", uid, fixture, location_builder=_location_builder)
    from schemas.scim import ENTERPRISE_USER_SCHEMA

    assert captured["displayName"] == "Robert Builder"
    assert captured["name"]["givenName"] == "Robert"
    assert captured[ENTERPRISE_USER_SCHEMA]["department"] == "Construction"
