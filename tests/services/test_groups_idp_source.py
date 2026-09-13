"""Tests for the ``source`` plumbing in services.groups.idp.

The IdP group functions default to the SAML source; these tests assert the
OIDC source is threaded through to the database layer and into the audit
metadata, and cover the base-group rename helper.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from services.exceptions import ConflictError

TENANT = str(uuid4())
CONN = str(uuid4())


@pytest.fixture
def mock_db():
    with patch("services.groups.idp.database") as db, patch("services.groups.idp.log_event") as log:
        yield db, log


def _events(log) -> list[dict]:
    return [c.kwargs for c in log.call_args_list]


class TestCreateBaseGroup:
    def test_oidc_source_reaches_database(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        gid = str(uuid4())
        db.groups.get_group_by_idp_and_name.return_value = None
        db.groups.create_idp_group.return_value = {"id": gid}
        db.groups.get_group_by_id.return_value = {
            "id": gid,
            "name": "Acme OIDC",
            "group_type": "idp",
            "oidc_connection_id": CONN,
            "is_valid": True,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }

        result = idp.create_idp_base_group(TENANT, CONN, "Acme OIDC", source="oidc")

        assert result.oidc_connection_id == CONN
        db.groups.get_group_by_idp_and_name.assert_called_once_with(
            TENANT, CONN, "Acme OIDC", "oidc"
        )
        assert db.groups.create_idp_group.call_args.kwargs["source"] == "oidc"
        created = [e for e in _events(log) if e["event_type"] == "idp_group_created"]
        assert created[0]["metadata"]["idp_source"] == "oidc"

    def test_duplicate_name_conflicts(self, mock_db):
        from services.groups import idp

        db, _ = mock_db
        db.groups.get_group_by_idp_and_name.return_value = {"id": "x"}

        with pytest.raises(ConflictError):
            idp.create_idp_base_group(TENANT, CONN, "Acme OIDC", source="oidc")

    def test_default_source_is_saml(self, mock_db):
        from services.groups import idp

        db, _ = mock_db
        db.groups.get_group_by_idp_and_name.return_value = {"id": "x"}
        with pytest.raises(ConflictError):
            idp.create_idp_base_group(TENANT, CONN, "SAML IdP")
        db.groups.get_group_by_idp_and_name.assert_called_once_with(
            TENANT, CONN, "SAML IdP", "saml"
        )


class TestSyncUserIdpGroups:
    def test_oidc_sync_threads_source_and_sync_source(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        base_id, existing_id, new_id = str(uuid4()), str(uuid4()), str(uuid4())
        # User is currently in the base group and an old group.
        db.groups.get_user_idp_group_ids.return_value = [base_id, existing_id]
        db.groups.get_idp_base_group_id.return_value = base_id
        db.groups.get_group_by_idp_and_name.return_value = None
        db.groups.create_idp_group.return_value = {"id": new_id}
        db.groups.relationship_exists.return_value = False
        db.groups.get_group_by_id.side_effect = lambda _t, gid: {"id": gid, "name": f"g-{gid[:4]}"}

        result = idp.sync_user_idp_groups(
            TENANT,
            "user-1",
            "u@example.com",
            CONN,
            "Acme OIDC",
            ["engineering"],
            source="oidc",
            sync_source="oidc_authentication",
        )

        assert result["created"] == ["engineering"]
        assert len(result["added"]) == 1
        assert len(result["removed"]) == 1

        db.groups.get_user_idp_group_ids.assert_called_once_with(TENANT, "user-1", CONN, "oidc")
        db.groups.get_idp_base_group_id.assert_any_call(TENANT, CONN, "oidc")
        db.groups.get_group_by_idp_and_name.assert_called_with(TENANT, CONN, "engineering", "oidc")
        assert db.groups.create_idp_group.call_args.kwargs["source"] == "oidc"

        # Base group is never removed by a claim sync.
        removed_ids = db.groups.bulk_remove_user_from_groups.call_args.args[2]
        assert base_id not in removed_ids
        assert existing_id in removed_ids

        # Umbrella wiring happened for the new group.
        db.groups.add_group_relationship.assert_called_once_with(TENANT, TENANT, base_id, new_id)

        member_events = [
            e
            for e in _events(log)
            if e["event_type"] in ("idp_group_member_added", "idp_group_member_removed")
        ]
        assert member_events
        for e in member_events:
            assert e["metadata"]["idp_source"] == "oidc"
            assert e["metadata"]["sync_source"] == "oidc_authentication"
        discovered = [e for e in _events(log) if e["event_type"] == "idp_group_discovered"]
        assert discovered[0]["metadata"]["idp_source"] == "oidc"

    def test_saml_default_metadata_unchanged(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        gid = str(uuid4())
        db.groups.get_user_idp_group_ids.return_value = []
        db.groups.get_idp_base_group_id.return_value = None
        db.groups.get_group_by_idp_and_name.return_value = {"id": gid, "name": "ops"}
        db.groups.get_group_by_id.return_value = {"id": gid, "name": "ops"}

        idp.sync_user_idp_groups(TENANT, "user-1", "u@example.com", "idp-1", "SAML", ["ops"])

        added = [e for e in _events(log) if e["event_type"] == "idp_group_member_added"]
        assert added[0]["metadata"]["sync_source"] == "saml_authentication"
        assert added[0]["metadata"]["idp_source"] == "saml"


class TestEnsureUserInBaseGroup:
    def test_oidc_source_auto_creates_base_group(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        db.groups.get_idp_base_group_id.return_value = None
        db.groups.is_group_member.return_value = False
        created = MagicMock()
        created.id = str(uuid4())

        with patch("services.groups.idp.create_idp_base_group", return_value=created) as create:
            idp.ensure_user_in_base_group(
                TENANT, "user-1", "u@example.com", CONN, "Acme OIDC", source="oidc"
            )

        create.assert_called_once_with(TENANT, CONN, "Acme OIDC", "oidc")
        db.groups.get_idp_base_group_id.assert_called_once_with(TENANT, CONN, "oidc")
        db.groups.bulk_add_user_to_groups.assert_called_once_with(
            TENANT, TENANT, "user-1", [created.id]
        )
        added = [e for e in _events(log) if e["event_type"] == "idp_group_member_added"]
        assert added[0]["metadata"]["idp_source"] == "oidc"
        assert added[0]["metadata"]["sync_source"] == "idp_assignment"

    def test_already_member_is_noop(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        db.groups.get_idp_base_group_id.return_value = "base"
        db.groups.is_group_member.return_value = True

        idp.ensure_user_in_base_group(TENANT, "user-1", "e", CONN, "Acme OIDC", source="oidc")

        db.groups.bulk_add_user_to_groups.assert_not_called()
        log.assert_not_called()


class TestInvalidateIdpGroups:
    def test_oidc_source_deletes_and_logs(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        db.groups.get_groups_by_idp.return_value = [{"id": "g1", "name": "Acme OIDC"}]
        db.groups.delete_groups_by_idp.return_value = 1

        count = idp.invalidate_idp_groups(TENANT, CONN, "Acme OIDC", source="oidc")

        assert count == 1
        db.groups.get_groups_by_idp.assert_called_once_with(TENANT, CONN, "oidc")
        db.groups.delete_groups_by_idp.assert_called_once_with(TENANT, CONN, "oidc")
        ev = _events(log)[0]
        assert ev["event_type"] == "idp_group_invalidated"
        assert ev["metadata"]["idp_source"] == "oidc"

    def test_no_groups_returns_zero(self, mock_db):
        from services.groups import idp

        db, _ = mock_db
        db.groups.get_groups_by_idp.return_value = []
        assert idp.invalidate_idp_groups(TENANT, CONN, "Acme OIDC", source="oidc") == 0
        db.groups.delete_groups_by_idp.assert_not_called()


class TestRenameIdpBaseGroup:
    def test_renames_and_logs(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        db.groups.get_group_by_idp_and_name.return_value = {"id": "g1", "name": "Old"}

        assert idp.rename_idp_base_group(TENANT, CONN, "Old", "New", source="oidc") is True

        db.groups.get_group_by_idp_and_name.assert_called_once_with(TENANT, CONN, "Old", "oidc")
        db.groups.update_group.assert_called_once_with(TENANT, "g1", name="New")
        ev = _events(log)[0]
        assert ev["event_type"] == "idp_group_renamed"
        assert ev["artifact_id"] == "g1"
        assert ev["metadata"] == {
            "idp_id": CONN,
            "idp_source": "oidc",
            "old_name": "Old",
            "new_name": "New",
        }

    def test_same_name_is_noop(self, mock_db):
        from services.groups import idp

        db, _ = mock_db
        assert idp.rename_idp_base_group(TENANT, CONN, "Same", "Same", source="oidc") is False
        db.groups.get_group_by_idp_and_name.assert_not_called()

    def test_missing_base_group_is_noop(self, mock_db):
        from services.groups import idp

        db, log = mock_db
        db.groups.get_group_by_idp_and_name.return_value = None
        assert idp.rename_idp_base_group(TENANT, CONN, "Old", "New", source="oidc") is False
        db.groups.update_group.assert_not_called()
        log.assert_not_called()


class TestHelpers:
    def test_umbrella_detection_uses_oidc_source(self):
        from services.groups import _helpers

        group = {"id": "g1", "group_type": "idp", "oidc_connection_id": CONN}
        with patch("services.groups._helpers.database") as db:
            db.groups.get_idp_base_group_id.return_value = "g1"
            assert _helpers._is_idp_umbrella_group(TENANT, group) is True
            db.groups.get_idp_base_group_id.assert_called_once_with(TENANT, CONN, "oidc")

    def test_umbrella_detection_uses_saml_source(self):
        from services.groups import _helpers

        group = {"id": "g1", "group_type": "idp", "idp_id": "idp-1"}
        with patch("services.groups._helpers.database") as db:
            db.groups.get_idp_base_group_id.return_value = "other"
            assert _helpers._is_idp_umbrella_group(TENANT, group) is False
            db.groups.get_idp_base_group_id.assert_called_once_with(TENANT, "idp-1", "saml")

    def test_orphaned_idp_group_is_not_umbrella(self):
        from services.groups import _helpers

        with patch("services.groups._helpers.database") as db:
            orphan = {"id": "g", "group_type": "idp"}
            assert _helpers._is_idp_umbrella_group(TENANT, orphan) is False
            db.groups.get_idp_base_group_id.assert_not_called()

    def test_managed_relationship_requires_same_source(self):
        from services.groups import _helpers

        parent = {"id": "p", "group_type": "idp", "oidc_connection_id": CONN}
        child_oidc = {"id": "c", "group_type": "idp", "oidc_connection_id": CONN}
        child_saml = {"id": "c", "group_type": "idp", "idp_id": CONN}
        with patch("services.groups._helpers.database") as db:
            db.groups.get_idp_base_group_id.return_value = "p"
            assert _helpers._is_idp_managed_relationship(TENANT, parent, child_oidc) is True
            assert _helpers._is_idp_managed_relationship(TENANT, parent, child_saml) is False
