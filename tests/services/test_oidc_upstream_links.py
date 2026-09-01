"""Tests for the per-user OIDC disconnect (unlink) path (Iteration 7).

Covers ``unlink_user_from_connection``: scrub fires, mirror rows dropped, link
removed, user inactivated + emails unverified, and the dedicated unlink event
is logged. Also covers the admin list helpers.
"""

import pytest
from services.exceptions import ForbiddenError, NotFoundError
from services.types import RequestingUser


def _make_requesting_user(user, tenant_id, role="super_admin"):
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role,
    )


def _make_connection(test_tenant, test_user, **overrides):
    import database

    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Iter7 OIDC",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=str(test_user["id"]),
        **overrides,
    )


def _link(test_tenant, connection, user, sub="subject-123"):
    import database

    return database.oidc_upstream.create_link(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        idp_id=str(connection["id"]),
        sub=sub,
        user_id=str(user["id"]),
    )


def _seed_and_mirror(test_tenant, test_super_admin_user, test_user, connection):
    """Seed tenant attribute config and mirror a job_title attribute."""
    from services.oidc_upstream.attributes import apply_oidc_idp_attributes
    from services.settings import attributes as attributes_settings

    requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
    attributes_settings.seed_tenant_attribute_config(test_tenant["id"])
    attributes_settings.update_tenant_attribute_config(
        requesting,
        "job_title",
        enabled=True,
        required=False,
        mirror_from_idp=True,
        locked_for_users=False,
        send_to_sps_default=False,
    )
    apply_oidc_idp_attributes(
        tenant_id=test_tenant["id"],
        user_id=str(test_user["id"]),
        idp_id=str(connection["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )


class TestUnlinkUser:
    def test_unlink_removes_link_and_scrubs(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)
        _seed_and_mirror(test_tenant, test_super_admin_user, test_user, conn)

        # Canonical attribute exists before unlink.
        assert (
            database.user_attributes.get_attribute(
                test_tenant["id"], str(test_user["id"]), "job_title"
            )
            is not None
        )

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))

        # Link removed.
        assert (
            database.oidc_upstream.get_user_id_by_sub(
                test_tenant["id"], str(conn["id"]), "subject-123"
            )
            is None
        )

        # Mirror rows dropped.
        assert (
            database.oidc_upstream.list_attributes_for_idp(
                test_tenant["id"], str(test_user["id"]), str(conn["id"])
            )
            == []
        )

        # Canonical attribute scrubbed.
        assert (
            database.user_attributes.get_attribute(
                test_tenant["id"], str(test_user["id"]), "job_title"
            )
            is None
        )

    def test_unlink_inactivates_and_unverifies(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))

        user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
        assert user["is_inactivated"] is True

        emails = database.user_emails.list_user_emails(test_tenant["id"], str(test_user["id"]))
        assert all(e["verified_at"] is None for e in emails)

    def test_unlink_logs_dedicated_event(self, test_tenant, test_super_admin_user, test_user):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))

        events = database.event_log.list_events(test_tenant["id"], limit=50)
        unlink_events = [
            e
            for e in events
            if e["event_type"] == "user_oidc_idp_unlinked"
            and str(e["artifact_id"]) == str(test_user["id"])
        ]
        assert len(unlink_events) == 1
        assert unlink_events[0]["metadata"]["idp_id"] == str(conn["id"])

    def test_unlink_unknown_connection_raises(self, test_tenant, test_super_admin_user, test_user):
        from uuid import uuid4

        from services import oidc_upstream as svc

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        with pytest.raises(NotFoundError) as exc_info:
            svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(uuid4()))
        assert exc_info.value.code == "oidc_connection_not_found"

    def test_unlink_user_not_linked_raises(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        with pytest.raises(NotFoundError) as exc_info:
            svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))
        assert exc_info.value.code == "oidc_user_link_not_found"

    def test_unlink_removes_all_links_for_user_idp(
        self, test_tenant, test_super_admin_user, test_user
    ):
        import database
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        # A user can hold multiple links against one connection (the schema
        # has no uniqueness on user_id, only on (idp_id, sub)).
        _link(test_tenant, conn, test_user, sub="subject-123")
        _link(test_tenant, conn, test_user, sub="subject-456")

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))

        assert (
            database.oidc_upstream.get_links_for_user_idp(
                test_tenant["id"], str(test_user["id"]), str(conn["id"])
            )
            == []
        )

    def test_unlink_as_admin_forbidden(self, test_tenant, test_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_admin_user)
        _link(test_tenant, conn, test_user)

        requesting = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
        with pytest.raises(ForbiddenError):
            svc.unlink_user_from_connection(requesting, str(test_user["id"]), str(conn["id"]))


class TestListHelpers:
    def test_list_connection_linked_users(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        users = svc.list_connection_linked_users(requesting, str(conn["id"]))
        assert len(users) == 1
        assert users[0]["user_id"] == str(test_user["id"])
        assert users[0]["sub"] == "subject-123"

    def test_list_user_oidc_links(self, test_tenant, test_super_admin_user, test_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        _link(test_tenant, conn, test_user)

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        links = svc.list_user_oidc_links(requesting, str(test_user["id"]))
        assert len(links) == 1
        assert links[0]["connection_id"] == str(conn["id"])
        assert links[0]["sub"] == "subject-123"
