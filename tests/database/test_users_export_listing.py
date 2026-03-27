"""Tests for list_all_users_for_export database query."""

import database


class TestListAllUsersForExport:
    """Tests for unbounded user listing for bulk export."""

    def test_returns_active_users_with_primary_email(self, test_tenant, test_admin_user):
        """Active users with a primary email are returned."""
        users = database.users.list_all_users_for_export(test_tenant["id"])

        assert len(users) >= 1
        # The test_admin_user should be present
        user_ids = [str(u["id"]) for u in users]
        assert str(test_admin_user["id"]) in user_ids

        # Verify returned fields
        admin_row = next(u for u in users if str(u["id"]) == str(test_admin_user["id"]))
        assert "first_name" in admin_row
        assert "last_name" in admin_row
        assert "email" in admin_row
        assert admin_row["email"] is not None

    def test_excludes_inactivated_users(self, test_tenant, test_user):
        """Inactivated users are excluded from the export."""
        user_id = str(test_user["id"])

        # Inactivate the user
        database.users.inactivate_user(test_tenant["id"], user_id)

        users = database.users.list_all_users_for_export(test_tenant["id"])
        user_ids = [str(u["id"]) for u in users]
        assert user_id not in user_ids

        # Reactivate for cleanup
        database.users.reactivate_user(test_tenant["id"], user_id)

    def test_excludes_anonymized_users(self, test_tenant, test_user):
        """Anonymized users are excluded from the export."""
        user_id = str(test_user["id"])

        database.users.anonymize_user(test_tenant["id"], user_id)

        users = database.users.list_all_users_for_export(test_tenant["id"])
        user_ids = [str(u["id"]) for u in users]
        assert user_id not in user_ids

    def test_excludes_service_users(self, test_tenant, b2b_oauth2_client):
        """Service users (B2B OAuth2 clients) are excluded."""
        service_user_id = str(b2b_oauth2_client["service_user_id"])

        users = database.users.list_all_users_for_export(test_tenant["id"])
        user_ids = [str(u["id"]) for u in users]
        assert service_user_id not in user_ids

    def test_returns_empty_for_empty_tenant(self, test_tenant):
        """Returns empty list when no active users match."""
        from uuid import uuid4

        # Query with a non-existent tenant to simulate empty
        users = database.users.list_all_users_for_export(str(uuid4()))
        assert users == []

    def test_ordered_by_last_name_first_name(self, test_tenant, test_admin_user, test_user):
        """Results are sorted by last_name, first_name ascending."""
        users = database.users.list_all_users_for_export(test_tenant["id"])

        if len(users) >= 2:
            for i in range(len(users) - 1):
                name_a = (
                    users[i]["last_name"].lower(),
                    users[i]["first_name"].lower(),
                )
                name_b = (
                    users[i + 1]["last_name"].lower(),
                    users[i + 1]["first_name"].lower(),
                )
                assert name_a <= name_b
