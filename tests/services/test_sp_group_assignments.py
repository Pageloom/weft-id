"""Tests for the SP group assignment service functions."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import ConflictError, ForbiddenError, NotFoundError

# =============================================================================
# Helpers
# =============================================================================


def _make_sp_row(
    tenant_id: str | None = None,
    sp_id: str | None = None,
    name: str = "Test App",
) -> dict:
    """Create a mock SP database row."""
    return {
        "id": sp_id or str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "name": name,
        "entity_id": "https://app.example.com",
        "acs_url": "https://app.example.com/acs",
        "certificate_pem": None,
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "metadata_xml": None,
        "description": None,
        "created_by": str(uuid4()),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }


def _make_group_row(
    tenant_id: str | None = None,
    group_id: str | None = None,
    name: str = "Test Group",
) -> dict:
    """Create a mock group database row."""
    return {
        "id": group_id or str(uuid4()),
        "tenant_id": tenant_id or str(uuid4()),
        "name": name,
        "description": "A test group",
        "group_type": "weftid",
        "parent_count": 0,
        "child_count": 0,
        "member_count": 0,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }


def _make_assignment_row(
    sp_id: str | None = None,
    group_id: str | None = None,
    group_name: str = "Test Group",
) -> dict:
    """Create a mock SP group assignment row (from SP perspective)."""
    return {
        "id": str(uuid4()),
        "sp_id": sp_id or str(uuid4()),
        "group_id": group_id or str(uuid4()),
        "group_name": group_name,
        "group_description": None,
        "group_type": "weftid",
        "assigned_by": str(uuid4()),
        "assigned_at": datetime.now(UTC),
    }


def _make_group_assignment_row(
    sp_id: str | None = None,
    group_id: str | None = None,
    sp_name: str = "Test App",
) -> dict:
    """Create a mock group SP assignment row (from group perspective)."""
    return {
        "id": str(uuid4()),
        "sp_id": sp_id or str(uuid4()),
        "group_id": group_id or str(uuid4()),
        "sp_name": sp_name,
        "sp_entity_id": "https://app.example.com",
        "sp_description": None,
        "assigned_by": str(uuid4()),
        "assigned_at": datetime.now(UTC),
    }


def _make_app_row(
    sp_id: str | None = None,
    name: str = "Test App",
) -> dict:
    """Create a mock accessible app row."""
    return {
        "id": sp_id or str(uuid4()),
        "name": name,
        "description": "A test app",
        "entity_id": "https://app.example.com",
    }


# =============================================================================
# list_sp_group_assignments
# =============================================================================


class TestListSPGroupAssignments:
    """Tests for list_sp_group_assignments."""

    def test_success_as_admin(self, make_requesting_user):
        """Admin can list SP group assignments."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)
        assignment_row = _make_assignment_row(sp_id=sp_id, group_id=group_id)

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.list_assignments_for_sp.return_value = [assignment_row]

            result = sp_service.list_sp_group_assignments(requesting_user, sp_id)

            assert result.total == 1
            assert len(result.items) == 1
            assert result.items[0].sp_id == sp_id
            assert result.items[0].group_id == str(assignment_row["group_id"])

    def test_success_as_super_admin(self, make_requesting_user):
        """Super admin can list SP group assignments."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.list_assignments_for_sp.return_value = []

            result = sp_service.list_sp_group_assignments(requesting_user, sp_id)

            assert result.total == 0
            assert result.items == []

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot list SP group assignments."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.list_sp_group_assignments(requesting_user, str(uuid4()))

    def test_sp_not_found(self, make_requesting_user):
        """Raises NotFoundError when SP does not exist."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.service_providers.get_service_provider.return_value = None

            with pytest.raises(NotFoundError, match="Service provider not found"):
                sp_service.list_sp_group_assignments(requesting_user, str(uuid4()))

    def test_tracks_activity(self, make_requesting_user):
        """Listing assignments tracks activity."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity") as mock_track,
        ):
            mock_db.service_providers.get_service_provider.return_value = _make_sp_row(
                tenant_id=tenant_id, sp_id=sp_id
            )
            mock_db.sp_group_assignments.list_assignments_for_sp.return_value = []

            sp_service.list_sp_group_assignments(requesting_user, sp_id)

            mock_track.assert_called_once_with(tenant_id, requesting_user["id"])


# =============================================================================
# assign_sp_to_group
# =============================================================================


class TestAssignSPToGroup:
    """Tests for assign_sp_to_group."""

    def test_success(self, make_requesting_user):
        """Admin can assign a group to an SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id, name="My App")
        group_row = _make_group_row(tenant_id=tenant_id, group_id=group_id, name="Engineering")
        create_row = {
            "id": str(uuid4()),
            "sp_id": sp_id,
            "group_id": group_id,
            "assigned_by": requesting_user["id"],
            "assigned_at": datetime.now(UTC),
        }

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event"),
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.groups.get_group_by_id.return_value = group_row
            mock_db.sp_group_assignments.create_assignment.return_value = create_row

            result = sp_service.assign_sp_to_group(requesting_user, sp_id, group_id)

            assert result.sp_id == sp_id
            assert result.group_id == group_id
            assert result.group_name == "Engineering"
            assert result.group_type == "weftid"

    def test_sp_not_found(self, make_requesting_user):
        """Raises NotFoundError when SP does not exist."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = None

            with pytest.raises(NotFoundError, match="Service provider not found"):
                sp_service.assign_sp_to_group(requesting_user, str(uuid4()), str(uuid4()))

    def test_group_not_found(self, make_requesting_user):
        """Raises NotFoundError when group does not exist."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = _make_sp_row(
                tenant_id=tenant_id, sp_id=sp_id
            )
            mock_db.groups.get_group_by_id.return_value = None

            with pytest.raises(NotFoundError, match="Group not found"):
                sp_service.assign_sp_to_group(requesting_user, sp_id, str(uuid4()))

    def test_already_assigned_conflict(self, make_requesting_user):
        """Raises ConflictError when group is already assigned."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = _make_sp_row(
                tenant_id=tenant_id, sp_id=sp_id
            )
            mock_db.groups.get_group_by_id.return_value = _make_group_row(
                tenant_id=tenant_id, group_id=group_id
            )
            mock_db.sp_group_assignments.create_assignment.return_value = None

            with pytest.raises(ConflictError, match="already assigned"):
                sp_service.assign_sp_to_group(requesting_user, sp_id, group_id)

    def test_logs_event(self, make_requesting_user):
        """Assigning a group logs an sp_group_assigned event."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id, name="My App")
        group_row = _make_group_row(tenant_id=tenant_id, group_id=group_id, name="Engineering")
        create_row = {
            "id": str(uuid4()),
            "sp_id": sp_id,
            "group_id": group_id,
            "assigned_by": requesting_user["id"],
            "assigned_at": datetime.now(UTC),
        }

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event") as mock_log,
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.groups.get_group_by_id.return_value = group_row
            mock_db.sp_group_assignments.create_assignment.return_value = create_row

            sp_service.assign_sp_to_group(requesting_user, sp_id, group_id)

            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["event_type"] == "sp_group_assigned"
            assert call_kwargs["artifact_id"] == sp_id
            assert call_kwargs["metadata"]["group_id"] == group_id
            assert call_kwargs["metadata"]["group_name"] == "Engineering"
            assert call_kwargs["metadata"]["sp_name"] == "My App"

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot assign groups to SPs."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.assign_sp_to_group(requesting_user, str(uuid4()), str(uuid4()))


# =============================================================================
# remove_sp_group_assignment
# =============================================================================


class TestRemoveSPGroupAssignment:
    """Tests for remove_sp_group_assignment."""

    def test_success(self, make_requesting_user):
        """Admin can remove a group assignment from an SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id, name="My App")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event"),
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.delete_assignment.return_value = 1

            sp_service.remove_sp_group_assignment(requesting_user, sp_id, group_id)

            mock_db.sp_group_assignments.delete_assignment.assert_called_once_with(
                tenant_id, sp_id, group_id
            )

    def test_sp_not_found(self, make_requesting_user):
        """Raises NotFoundError when SP does not exist."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = None

            with pytest.raises(NotFoundError, match="Service provider not found"):
                sp_service.remove_sp_group_assignment(requesting_user, str(uuid4()), str(uuid4()))

    def test_assignment_not_found(self, make_requesting_user):
        """Raises NotFoundError when assignment does not exist."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = _make_sp_row(
                tenant_id=tenant_id, sp_id=sp_id
            )
            mock_db.sp_group_assignments.delete_assignment.return_value = 0

            with pytest.raises(NotFoundError, match="Group assignment not found"):
                sp_service.remove_sp_group_assignment(requesting_user, sp_id, str(uuid4()))

    def test_logs_event(self, make_requesting_user):
        """Removing an assignment logs an sp_group_unassigned event."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id, name="My App")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event") as mock_log,
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.delete_assignment.return_value = 1

            sp_service.remove_sp_group_assignment(requesting_user, sp_id, group_id)

            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["event_type"] == "sp_group_unassigned"
            assert call_kwargs["artifact_id"] == sp_id
            assert call_kwargs["metadata"]["group_id"] == group_id
            assert call_kwargs["metadata"]["sp_name"] == "My App"

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot remove group assignments."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.remove_sp_group_assignment(requesting_user, str(uuid4()), str(uuid4()))


# =============================================================================
# bulk_assign_sp_to_groups
# =============================================================================


class TestBulkAssignSPToGroups:
    """Tests for bulk_assign_sp_to_groups."""

    def test_success(self, make_requesting_user):
        """Admin can bulk-assign groups to an SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_ids = [str(uuid4()), str(uuid4()), str(uuid4())]
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id, name="My App")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event"),
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.bulk_create_assignments.return_value = 3

            result = sp_service.bulk_assign_sp_to_groups(requesting_user, sp_id, group_ids)

            assert result == 3
            mock_db.sp_group_assignments.bulk_create_assignments.assert_called_once_with(
                tenant_id=tenant_id,
                tenant_id_value=tenant_id,
                sp_id=sp_id,
                group_ids=group_ids,
                assigned_by=requesting_user["id"],
            )

    def test_sp_not_found(self, make_requesting_user):
        """Raises NotFoundError when SP does not exist."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.get_service_provider.return_value = None

            with pytest.raises(NotFoundError, match="Service provider not found"):
                sp_service.bulk_assign_sp_to_groups(requesting_user, str(uuid4()), [str(uuid4())])

    def test_logs_event_with_count(self, make_requesting_user):
        """Bulk assign logs sp_groups_bulk_assigned event with count."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_ids = [str(uuid4()), str(uuid4())]
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id, name="My App")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event") as mock_log,
        ):
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.bulk_create_assignments.return_value = 2

            sp_service.bulk_assign_sp_to_groups(requesting_user, sp_id, group_ids)

            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert call_kwargs["event_type"] == "sp_groups_bulk_assigned"
            assert call_kwargs["artifact_id"] == sp_id
            assert call_kwargs["metadata"]["count"] == 2
            assert call_kwargs["metadata"]["group_ids"] == group_ids
            assert call_kwargs["metadata"]["sp_name"] == "My App"

    def test_no_event_when_zero_assigned(self, make_requesting_user):
        """No event is logged when zero assignments are created."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event") as mock_log,
        ):
            mock_db.service_providers.get_service_provider.return_value = _make_sp_row(
                tenant_id=tenant_id, sp_id=sp_id
            )
            mock_db.sp_group_assignments.bulk_create_assignments.return_value = 0

            result = sp_service.bulk_assign_sp_to_groups(requesting_user, sp_id, [str(uuid4())])

            assert result == 0
            mock_log.assert_not_called()

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot bulk-assign groups."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.bulk_assign_sp_to_groups(requesting_user, str(uuid4()), [str(uuid4())])


# =============================================================================
# list_group_sp_assignments
# =============================================================================


class TestListGroupSPAssignments:
    """Tests for list_group_sp_assignments."""

    def test_success(self, make_requesting_user):
        """Admin can list SP assignments for a group."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        group_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        group_row = _make_group_row(tenant_id=tenant_id, group_id=group_id)
        assignment_row = _make_group_assignment_row(
            sp_id=sp_id, group_id=group_id, sp_name="My App"
        )

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.groups.get_group_by_id.return_value = group_row
            mock_db.sp_group_assignments.list_assignments_for_group.return_value = [assignment_row]

            result = sp_service.list_group_sp_assignments(requesting_user, group_id)

            assert result.total == 1
            assert len(result.items) == 1
            assert result.items[0].sp_name == "My App"
            assert result.items[0].group_id == str(assignment_row["group_id"])

    def test_group_not_found(self, make_requesting_user):
        """Raises NotFoundError when group does not exist."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.groups.get_group_by_id.return_value = None

            with pytest.raises(NotFoundError, match="Group not found"):
                sp_service.list_group_sp_assignments(requesting_user, str(uuid4()))

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot list group SP assignments."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.list_group_sp_assignments(requesting_user, str(uuid4()))

    def test_tracks_activity(self, make_requesting_user):
        """Listing group SP assignments tracks activity."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity") as mock_track,
        ):
            mock_db.groups.get_group_by_id.return_value = _make_group_row(
                tenant_id=tenant_id, group_id=group_id
            )
            mock_db.sp_group_assignments.list_assignments_for_group.return_value = []

            sp_service.list_group_sp_assignments(requesting_user, group_id)

            mock_track.assert_called_once_with(tenant_id, requesting_user["id"])


# =============================================================================
# list_available_groups_for_sp
# =============================================================================


class TestListAvailableGroupsForSP:
    """Tests for list_available_groups_for_sp."""

    def test_success_filters_out_assigned(self, make_requesting_user):
        """Returns only groups not yet assigned to the SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_a_id = str(uuid4())
        group_b_id = str(uuid4())
        group_c_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        all_groups = [
            {
                "id": group_a_id,
                "name": "Group A",
                "group_type": "weftid",
            },
            {
                "id": group_b_id,
                "name": "Group B",
                "group_type": "weftid",
            },
            {
                "id": group_c_id,
                "name": "Group C",
                "group_type": "idp",
            },
        ]

        # Group B is already assigned
        assigned_rows = [
            _make_assignment_row(sp_id=sp_id, group_id=group_b_id),
        ]

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.groups.list_groups.return_value = all_groups
            mock_db.sp_group_assignments.list_assignments_for_sp.return_value = assigned_rows

            result = sp_service.list_available_groups_for_sp(requesting_user, sp_id)

            assert len(result) == 2
            result_ids = {g["id"] for g in result}
            assert group_a_id in result_ids
            assert group_c_id in result_ids
            assert group_b_id not in result_ids

    def test_all_groups_assigned(self, make_requesting_user):
        """Returns empty list when all groups are assigned."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        all_groups = [
            {"id": group_id, "name": "Only Group", "group_type": "weftid"},
        ]
        assigned_rows = [
            _make_assignment_row(sp_id=sp_id, group_id=group_id),
        ]

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.groups.list_groups.return_value = all_groups
            mock_db.sp_group_assignments.list_assignments_for_sp.return_value = assigned_rows

            result = sp_service.list_available_groups_for_sp(requesting_user, sp_id)

            assert result == []

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot list available groups."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.list_available_groups_for_sp(requesting_user, str(uuid4()))

    def test_tracks_activity(self, make_requesting_user):
        """Admin activity is tracked for this read operation."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity") as mock_track,
        ):
            mock_db.groups.list_groups.return_value = []
            mock_db.sp_group_assignments.list_assignments_for_sp.return_value = []

            sp_service.list_available_groups_for_sp(requesting_user, sp_id)

        mock_track.assert_called_once_with(tenant_id, requesting_user["id"])


# =============================================================================
# check_user_sp_access
# =============================================================================


class TestCheckUserSPAccess:
    """Tests for check_user_sp_access."""

    def test_returns_true_when_access(self):
        """Returns True when user has access via group membership."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.sp_group_assignments.user_can_access_sp.return_value = True

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is True
            mock_db.sp_group_assignments.user_can_access_sp.assert_called_once_with(
                tenant_id, user_id, sp_id
            )

    def test_returns_false_when_no_access(self):
        """Returns False when user has no access."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.sp_group_assignments.user_can_access_sp.return_value = False

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is False


# =============================================================================
# check_user_sp_access - hierarchy scenarios
# =============================================================================


class TestCheckUserSPAccessScenarios:
    """Extended scenarios documenting hierarchy-based access via the DAG closure table.

    Each test mocks database.sp_group_assignments.user_can_access_sp to verify
    the service delegates correctly. The actual hierarchy resolution happens in
    the SQL query (using group_lineage), so these tests document the *intended*
    semantics at the service layer.
    """

    def test_access_via_direct_group_membership(self):
        """User in a directly-assigned group can access the SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.sp_group_assignments.user_can_access_sp.return_value = True

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is True
            mock_db.sp_group_assignments.user_can_access_sp.assert_called_once_with(
                tenant_id, user_id, sp_id
            )

    def test_access_via_descendant_group(self):
        """User in a child of an assigned group can access the SP (depth=1)."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            # DB query joins group_lineage, so child membership resolves to True
            mock_db.sp_group_assignments.user_can_access_sp.return_value = True

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is True

    def test_access_via_deep_descendant(self):
        """User in a grandchild group can access the SP (depth=2)."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            # Deep hierarchy: grandchild membership resolves via closure table
            mock_db.sp_group_assignments.user_can_access_sp.return_value = True

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is True

    def test_no_access_sp_has_zero_assignments(self):
        """Deny-by-default: SP with no group assignments denies all users."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.sp_group_assignments.user_can_access_sp.return_value = False

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is False

    def test_no_access_user_in_unrelated_group(self):
        """User in group C is denied when SP is assigned only to group A."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            # User's group has no lineage relationship to the assigned group
            mock_db.sp_group_assignments.user_can_access_sp.return_value = False

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is False

    def test_no_access_after_group_unassigned(self, make_requesting_user):
        """Revocation: removing group assignment revokes access."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        group_id = str(uuid4())
        user_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")
        sp_row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.log_event"),
        ):
            # Step 1: remove the group assignment
            mock_db.service_providers.get_service_provider.return_value = sp_row
            mock_db.sp_group_assignments.delete_assignment.return_value = 1

            sp_service.remove_sp_group_assignment(requesting_user, sp_id, group_id)

            # Step 2: verify access is now denied
            mock_db.sp_group_assignments.user_can_access_sp.return_value = False

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is False

    def test_no_access_after_user_removed_from_group(self):
        """Revocation: user removed from group loses SP access (group still assigned)."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        user_id = str(uuid4())
        sp_id = str(uuid4())

        with patch("services.service_providers.group_assignments.database") as mock_db:
            # Group is still assigned to SP, but user is no longer a member
            mock_db.sp_group_assignments.user_can_access_sp.return_value = False

            result = sp_service.check_user_sp_access(tenant_id, user_id, sp_id)

            assert result is False


# =============================================================================
# list_service_providers - assignment count enrichment
# =============================================================================


class TestListSPAssignmentCounts:
    """Tests for assigned_group_count enrichment in list_service_providers."""

    def test_sp_with_assignments_shows_count(self, make_requesting_user):
        """SP with group assignments shows the correct count."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)

        with (
            patch("services.service_providers.crud.database") as mock_db,
            patch("services.service_providers.crud.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = [row]
            mock_db.sp_group_assignments.count_assignments_for_sps.return_value = {sp_id: 5}
            mock_db.sp_signing_certificates.get_signing_certificate.return_value = None

            result = sp_service.list_service_providers(requesting_user)

            assert result.items[0].assigned_group_count == 5

    def test_sp_with_zero_assignments_shows_zero(self, make_requesting_user):
        """SP not in count map defaults to zero."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id)

        with (
            patch("services.service_providers.crud.database") as mock_db,
            patch("services.service_providers.crud.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = [row]
            mock_db.sp_group_assignments.count_assignments_for_sps.return_value = {}
            mock_db.sp_signing_certificates.get_signing_certificate.return_value = None

            result = sp_service.list_service_providers(requesting_user)

            assert result.items[0].assigned_group_count == 0

    def test_multiple_sps_with_different_counts(self, make_requesting_user):
        """Each SP gets its own assignment count."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id_1 = str(uuid4())
        sp_id_2 = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row_1 = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id_1, name="App 1")
        row_2 = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id_2, name="App 2")

        with (
            patch("services.service_providers.crud.database") as mock_db,
            patch("services.service_providers.crud.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = [row_1, row_2]
            mock_db.sp_group_assignments.count_assignments_for_sps.return_value = {
                sp_id_1: 3,
                sp_id_2: 7,
            }
            mock_db.sp_signing_certificates.get_signing_certificate.return_value = None

            result = sp_service.list_service_providers(requesting_user)

            assert result.items[0].assigned_group_count == 3
            assert result.items[1].assigned_group_count == 7

    def test_count_defaults_to_zero_for_unlisted_sp(self, make_requesting_user):
        """SP missing from count map gets 0, while listed SP gets its count."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id_1 = str(uuid4())
        sp_id_2 = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")
        row_1 = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id_1, name="Listed")
        row_2 = _make_sp_row(tenant_id=tenant_id, sp_id=sp_id_2, name="Unlisted")

        with (
            patch("services.service_providers.crud.database") as mock_db,
            patch("services.service_providers.crud.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = [row_1, row_2]
            # Only sp_id_1 in the count map
            mock_db.sp_group_assignments.count_assignments_for_sps.return_value = {sp_id_1: 2}
            mock_db.sp_signing_certificates.get_signing_certificate.return_value = None

            result = sp_service.list_service_providers(requesting_user)

            assert result.items[0].assigned_group_count == 2
            assert result.items[1].assigned_group_count == 0

    def test_empty_sp_list_skips_enrichment(self, make_requesting_user):
        """Empty SP list still calls count but produces no items."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="super_admin")

        with (
            patch("services.service_providers.crud.database") as mock_db,
            patch("services.service_providers.crud.track_activity"),
        ):
            mock_db.service_providers.list_service_providers.return_value = []
            mock_db.sp_group_assignments.count_assignments_for_sps.return_value = {}

            result = sp_service.list_service_providers(requesting_user)

            assert result.total == 0
            assert result.items == []
            mock_db.sp_group_assignments.count_assignments_for_sps.assert_called_once_with(
                tenant_id
            )


# =============================================================================
# get_user_accessible_apps
# =============================================================================


class TestGetUserAccessibleApps:
    """Tests for get_user_accessible_apps."""

    def test_success_with_apps(self, make_requesting_user):
        """Returns accessible apps for the user."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id_1 = str(uuid4())
        sp_id_2 = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")
        app_rows = [
            _make_app_row(sp_id=sp_id_1, name="App One"),
            _make_app_row(sp_id=sp_id_2, name="App Two"),
        ]

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = app_rows

            result = sp_service.get_user_accessible_apps(requesting_user)

            assert result.total == 2
            assert len(result.items) == 2
            assert result.items[0].name == "App One"
            assert result.items[1].name == "App Two"
            assert result.items[0].id == sp_id_1

    def test_empty_result(self, make_requesting_user):
        """Returns empty list when user has no accessible apps."""
        from services import service_providers as sp_service

        requesting_user = make_requesting_user(role="user")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = []

            result = sp_service.get_user_accessible_apps(requesting_user)

            assert result.total == 0
            assert result.items == []

    def test_tracks_activity(self, make_requesting_user):
        """Getting accessible apps tracks activity."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity") as mock_track,
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = []

            sp_service.get_user_accessible_apps(requesting_user)

            mock_track.assert_called_once_with(tenant_id, requesting_user["id"])

    def test_any_role_can_access(self, make_requesting_user):
        """Any authenticated user (including regular user) can get their apps."""
        from services import service_providers as sp_service

        for role in ("user", "admin", "super_admin"):
            requesting_user = make_requesting_user(role=role)

            with (
                patch("services.service_providers.group_assignments.database") as mock_db,
                patch("services.service_providers.group_assignments.track_activity"),
            ):
                mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = []

                result = sp_service.get_user_accessible_apps(requesting_user)

                assert result.total == 0


# =============================================================================
# get_user_accessible_apps - extended scenarios
# =============================================================================


class TestGetUserAccessibleAppsExtended:
    """Extended scenarios for get_user_accessible_apps: field mapping, ordering."""

    def test_multiple_apps_via_different_groups(self, make_requesting_user):
        """Multiple apps are returned when user has access via different groups."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")
        app_rows = [
            _make_app_row(name="App A"),
            _make_app_row(name="App B"),
            _make_app_row(name="App C"),
        ]

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = app_rows

            result = sp_service.get_user_accessible_apps(requesting_user)

            assert result.total == 3
            assert [item.name for item in result.items] == ["App A", "App B", "App C"]

    def test_single_app_when_db_deduplicates(self, make_requesting_user):
        """DB returns 1 row (DISTINCT handles duplicates), verify 1 result."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")
        app_rows = [_make_app_row(sp_id=sp_id, name="Shared App")]

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = app_rows

            result = sp_service.get_user_accessible_apps(requesting_user)

            assert result.total == 1
            assert result.items[0].id == sp_id
            assert result.items[0].name == "Shared App"

    def test_maps_all_fields_correctly(self, make_requesting_user):
        """Verify id, name, description, entity_id are mapped from row to UserApp."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")
        app_row = {
            "id": sp_id,
            "name": "Full App",
            "description": "A complete application",
            "entity_id": "https://fullapp.example.com",
        }

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = [app_row]

            result = sp_service.get_user_accessible_apps(requesting_user)

            item = result.items[0]
            assert item.id == sp_id
            assert item.name == "Full App"
            assert item.description == "A complete application"
            assert item.entity_id == "https://fullapp.example.com"

    def test_description_is_optional(self, make_requesting_user):
        """Row with description=None produces UserApp with description=None."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")
        app_row = {
            "id": str(uuid4()),
            "name": "No Desc App",
            "entity_id": "https://nodesc.example.com",
        }

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = [app_row]

            result = sp_service.get_user_accessible_apps(requesting_user)

            assert result.items[0].description is None

    def test_apps_ordered_by_name(self, make_requesting_user):
        """Result preserves DB ordering (alphabetical by name)."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="user")
        app_rows = [
            _make_app_row(name="Alpha"),
            _make_app_row(name="Beta"),
            _make_app_row(name="Gamma"),
        ]

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.get_accessible_sps_for_user.return_value = app_rows

            result = sp_service.get_user_accessible_apps(requesting_user)

            names = [item.name for item in result.items]
            assert names == ["Alpha", "Beta", "Gamma"]


# =============================================================================
# count_sp_group_assignments
# =============================================================================


class TestCountSPGroupAssignments:
    """Tests for count_sp_group_assignments."""

    def test_returns_count(self, make_requesting_user):
        """Returns the count of group assignments for an SP."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity"),
        ):
            mock_db.sp_group_assignments.count_assignments_for_sp.return_value = 3

            result = sp_service.count_sp_group_assignments(requesting_user, sp_id)

            assert result == 3
            mock_db.sp_group_assignments.count_assignments_for_sp.assert_called_once_with(
                tenant_id, sp_id
            )

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot count assignments."""
        from services import service_providers as sp_service
        from services.exceptions import ForbiddenError

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.count_sp_group_assignments(requesting_user, str(uuid4()))

    def test_tracks_activity(self, make_requesting_user):
        """Admin activity is tracked for this read operation."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity") as mock_track,
        ):
            mock_db.sp_group_assignments.count_assignments_for_sp.return_value = 0

            sp_service.count_sp_group_assignments(requesting_user, sp_id)

            mock_track.assert_called_once_with(tenant_id, requesting_user["id"])


# =============================================================================
# list_available_sps_for_group
# =============================================================================


class TestListAvailableSPsForGroup:
    """Tests for list_available_sps_for_group."""

    def test_filters_out_assigned_sps(self, make_requesting_user):
        """Returns only SPs not yet assigned to the group."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        group_id = str(uuid4())
        sp_a_id = str(uuid4())
        sp_b_id = str(uuid4())
        sp_c_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        all_sps = [
            {"id": sp_a_id, "name": "App A"},
            {"id": sp_b_id, "name": "App B"},
            {"id": sp_c_id, "name": "App C"},
        ]
        # App B is already assigned
        assigned_rows = [
            {
                "sp_id": sp_b_id,
                "group_id": group_id,
                "sp_name": "App B",
                "sp_entity_id": "https://b.example.com",
                "assigned_by": str(uuid4()),
                "assigned_at": None,
            }
        ]

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.list_service_providers.return_value = all_sps
            mock_db.sp_group_assignments.list_assignments_for_group.return_value = assigned_rows

            result = sp_service.list_available_sps_for_group(requesting_user, group_id)

            assert len(result) == 2
            result_ids = {sp["id"] for sp in result}
            assert sp_a_id in result_ids
            assert sp_c_id in result_ids
            assert sp_b_id not in result_ids

    def test_returns_empty_when_all_assigned(self, make_requesting_user):
        """Returns empty list when all SPs are already assigned."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        group_id = str(uuid4())
        sp_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        all_sps = [{"id": sp_id, "name": "Only App"}]
        assigned_rows = [
            {
                "sp_id": sp_id,
                "group_id": group_id,
                "sp_name": "Only App",
                "sp_entity_id": "https://app.example.com",
                "assigned_by": str(uuid4()),
                "assigned_at": None,
            }
        ]

        with patch("services.service_providers.group_assignments.database") as mock_db:
            mock_db.service_providers.list_service_providers.return_value = all_sps
            mock_db.sp_group_assignments.list_assignments_for_group.return_value = assigned_rows

            result = sp_service.list_available_sps_for_group(requesting_user, group_id)

            assert result == []

    def test_forbidden_for_user(self, make_requesting_user):
        """Regular user cannot list available SPs."""
        from services import service_providers as sp_service
        from services.exceptions import ForbiddenError

        requesting_user = make_requesting_user(role="user")

        with pytest.raises(ForbiddenError):
            sp_service.list_available_sps_for_group(requesting_user, str(uuid4()))

    def test_tracks_activity(self, make_requesting_user):
        """Admin activity is tracked for this read operation."""
        from services import service_providers as sp_service

        tenant_id = str(uuid4())
        group_id = str(uuid4())
        requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

        with (
            patch("services.service_providers.group_assignments.database") as mock_db,
            patch("services.service_providers.group_assignments.track_activity") as mock_track,
        ):
            mock_db.service_providers.list_service_providers.return_value = []
            mock_db.sp_group_assignments.list_assignments_for_group.return_value = []

            sp_service.list_available_sps_for_group(requesting_user, group_id)

            mock_track.assert_called_once_with(tenant_id, requesting_user["id"])
