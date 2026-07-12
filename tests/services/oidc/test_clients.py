"""Service tests for OIDC client management (services.oidc.clients).

Covers the oidc_enabled / available_to_all toggles, discovery-URL assembly,
group-assignment CRUD, authorization, and event logging.
"""

from unittest.mock import patch
from uuid import uuid4

import database
import pytest
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationError
from services.oidc import clients as svc


def _admin(test_tenant, test_admin_user):
    return {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }


def _member(test_tenant, test_user):
    return {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }


def _client(test_tenant, test_admin_user, name="Svc OIDC App"):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
    )


def _group(test_tenant, name="Svc Group"):
    return database.groups.create_group(
        tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name=name
    )


def _oidc_client(test_tenant, test_admin_user, *, available_to_all=False, name="Svc OIDC App"):
    """A normal client flipped to oidc_enabled (and optionally available_to_all)."""
    client = _client(test_tenant, test_admin_user, name=name)
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true, available_to_all = :ata where id = :id",
        {"id": client["id"], "ata": available_to_all},
    )
    return database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])


def _seed_tokens(test_tenant, client, test_user):
    """Create one access + one refresh token for a client (to observe revocation)."""
    database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client["id"]),
        user_id=str(test_user["id"]),
    )
    database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client["id"]),
        user_id=str(test_user["id"]),
    )


def _token_count(test_tenant, client):
    row = database.fetchone(
        test_tenant["id"],
        "select count(*) as n from oauth2_tokens where client_id = :cid",
        {"cid": str(client["id"])},
    )
    return row["n"]


class TestSetOidcSettings:
    def test_enable_oidc_persists_and_logs(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        with patch("services.oidc.clients.log_event") as log:
            updated = svc.set_oidc_settings(
                _admin(test_tenant, test_admin_user), client["client_id"], oidc_enabled=True
            )
        assert updated["oidc_enabled"] is True
        assert log.call_args.kwargs["event_type"] == "oidc_client_enabled"
        fresh = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        assert fresh["oidc_enabled"] is True

    def test_disable_oidc_logs_disabled_event(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        svc.set_oidc_settings(
            _admin(test_tenant, test_admin_user), client["client_id"], oidc_enabled=True
        )
        with patch("services.oidc.clients.log_event") as log:
            svc.set_oidc_settings(
                _admin(test_tenant, test_admin_user), client["client_id"], oidc_enabled=False
            )
        assert log.call_args.kwargs["event_type"] == "oidc_client_disabled"

    def test_no_event_when_value_unchanged(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        with patch("services.oidc.clients.log_event") as log:
            svc.set_oidc_settings(
                _admin(test_tenant, test_admin_user), client["client_id"], oidc_enabled=False
            )
        log.assert_not_called()

    def test_available_to_all_logs_availability_event(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        with patch("services.oidc.clients.log_event") as log:
            updated = svc.set_oidc_settings(
                _admin(test_tenant, test_admin_user), client["client_id"], available_to_all=True
            )
        assert updated["available_to_all"] is True
        assert log.call_args.kwargs["event_type"] == "oidc_client_availability_changed"

    def test_member_forbidden(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        with pytest.raises(ForbiddenError):
            svc.set_oidc_settings(
                _member(test_tenant, test_user), client["client_id"], oidc_enabled=True
            )

    def test_unknown_client_not_found(self, test_tenant, test_admin_user):
        with pytest.raises(NotFoundError):
            svc.set_oidc_settings(
                _admin(test_tenant, test_admin_user), "weft-id_client_missing", oidc_enabled=True
            )

    def test_b2b_client_rejected(self, test_tenant, test_admin_user):
        b2b = database.oauth2.create_b2b_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Svc B2B",
            role="admin",
            created_by=str(test_admin_user["id"]),
        )
        with pytest.raises(ValidationError):
            svc.set_oidc_settings(
                _admin(test_tenant, test_admin_user), b2b["client_id"], oidc_enabled=True
            )


class TestDiscoveryInfo:
    def test_urls_derived_from_base(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        info = svc.get_client_discovery_info(
            _admin(test_tenant, test_admin_user), client["client_id"], "https://acme.example.com"
        )
        assert info.issuer == "https://acme.example.com"
        assert info.discovery_url == "https://acme.example.com/.well-known/openid-configuration"
        assert info.jwks_uri == "https://acme.example.com/.well-known/jwks.json"
        assert info.authorization_endpoint == "https://acme.example.com/oauth2/authorize"
        assert info.token_endpoint == "https://acme.example.com/oauth2/token"
        assert info.userinfo_endpoint == "https://acme.example.com/userinfo"


class TestGroupAssignments:
    def test_assign_list_remove(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Assign Me")
        admin = _admin(test_tenant, test_admin_user)

        assignment = svc.assign_client_to_group(admin, client["client_id"], group["id"])
        assert assignment.group_name == "Assign Me"

        listing = svc.list_client_group_assignments(admin, client["client_id"])
        assert listing.total == 1
        assert listing.items[0].group_id == str(group["id"])

        svc.remove_client_group_assignment(admin, client["client_id"], group["id"])
        assert svc.list_client_group_assignments(admin, client["client_id"]).total == 0

    def test_assign_duplicate_conflict(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Dup Assign")
        admin = _admin(test_tenant, test_admin_user)
        svc.assign_client_to_group(admin, client["client_id"], group["id"])
        with pytest.raises(ConflictError):
            svc.assign_client_to_group(admin, client["client_id"], group["id"])

    def test_assign_unknown_group(self, test_tenant, test_admin_user):
        from uuid import uuid4

        client = _client(test_tenant, test_admin_user)
        with pytest.raises(NotFoundError):
            svc.assign_client_to_group(
                _admin(test_tenant, test_admin_user), client["client_id"], str(uuid4())
            )

    def test_remove_missing_assignment(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Never Assigned")
        with pytest.raises(NotFoundError):
            svc.remove_client_group_assignment(
                _admin(test_tenant, test_admin_user), client["client_id"], group["id"]
            )

    def test_bulk_assign_and_available_groups(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        g1 = _group(test_tenant, name="Bulk A")
        g2 = _group(test_tenant, name="Bulk B")
        admin = _admin(test_tenant, test_admin_user)

        count = svc.bulk_assign_client_to_groups(admin, client["client_id"], [g1["id"], g2["id"]])
        assert count == 2

        available = svc.list_available_groups_for_client(admin, client["client_id"])
        available_ids = {g["id"] for g in available}
        assert str(g1["id"]) not in available_ids
        assert str(g2["id"]) not in available_ids

    def test_bulk_assign_logs_event(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        g1 = _group(test_tenant, name="Bulk Log A")
        g2 = _group(test_tenant, name="Bulk Log B")
        admin = _admin(test_tenant, test_admin_user)
        with patch("services.oidc.clients.log_event") as log:
            svc.bulk_assign_client_to_groups(admin, client["client_id"], [g1["id"], g2["id"]])
        assert log.call_args.kwargs["event_type"] == "oidc_client_groups_bulk_assigned"
        assert log.call_args.kwargs["metadata"]["count"] == 2

    def test_bulk_assign_empty_is_noop(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        admin = _admin(test_tenant, test_admin_user)
        with patch("services.oidc.clients.log_event") as log:
            count = svc.bulk_assign_client_to_groups(admin, client["client_id"], [])
        assert count == 0
        log.assert_not_called()

    def test_bulk_assign_partial_duplicate_counts_only_new(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        g1 = _group(test_tenant, name="Partial A")
        g2 = _group(test_tenant, name="Partial B")
        admin = _admin(test_tenant, test_admin_user)
        svc.assign_client_to_group(admin, client["client_id"], g1["id"])
        # g1 is already assigned; only g2 is new.
        count = svc.bulk_assign_client_to_groups(admin, client["client_id"], [g1["id"], g2["id"]])
        assert count == 1
        assert svc.list_client_group_assignments(admin, client["client_id"]).total == 2

    def test_assign_logs_event(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Assign Log")
        admin = _admin(test_tenant, test_admin_user)
        with patch("services.oidc.clients.log_event") as log:
            svc.assign_client_to_group(admin, client["client_id"], group["id"])
        assert log.call_args.kwargs["event_type"] == "oidc_client_group_assigned"

    def test_unassign_logs_event(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Unassign Log")
        admin = _admin(test_tenant, test_admin_user)
        svc.assign_client_to_group(admin, client["client_id"], group["id"])
        with patch("services.oidc.clients.log_event") as log:
            svc.remove_client_group_assignment(admin, client["client_id"], group["id"])
        assert log.call_args.kwargs["event_type"] == "oidc_client_group_unassigned"

    def test_assign_group_to_b2b_client_rejected(self, test_tenant, test_admin_user):
        b2b = database.oauth2.create_b2b_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Grp B2B",
            role="admin",
            created_by=str(test_admin_user["id"]),
        )
        group = _group(test_tenant, name="B2B Group")
        with pytest.raises(ValidationError):
            svc.assign_client_to_group(
                _admin(test_tenant, test_admin_user), b2b["client_id"], group["id"]
            )

    def test_group_ops_member_forbidden(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Forbidden Group")
        with pytest.raises(ForbiddenError):
            svc.assign_client_to_group(
                _member(test_tenant, test_user), client["client_id"], group["id"]
            )


class TestGrantWithdrawalRevokesTokens:
    """Withdrawing an OIDC grant must revoke the tokens that grant produced, so a
    revoked user cannot keep refreshing for the 30-day refresh window."""

    def test_remove_group_assignment_revokes_tokens(self, test_tenant, test_admin_user, test_user):
        client = _oidc_client(test_tenant, test_admin_user)
        group = _group(test_tenant, name="Revoke On Remove")
        admin = _admin(test_tenant, test_admin_user)
        svc.assign_client_to_group(admin, client["client_id"], group["id"])
        _seed_tokens(test_tenant, client, test_user)
        assert _token_count(test_tenant, client) == 2

        svc.remove_client_group_assignment(admin, client["client_id"], group["id"])

        assert _token_count(test_tenant, client) == 0

    def test_remove_assignment_on_available_to_all_keeps_tokens(
        self, test_tenant, test_admin_user, test_user
    ):
        """available_to_all clients don't derive access from group assignments, so
        removing one revokes nobody and must not force everyone to re-authorize."""
        client = _oidc_client(test_tenant, test_admin_user, available_to_all=True)
        group = _group(test_tenant, name="ATA Assign")
        admin = _admin(test_tenant, test_admin_user)
        svc.assign_client_to_group(admin, client["client_id"], group["id"])
        _seed_tokens(test_tenant, client, test_user)

        svc.remove_client_group_assignment(admin, client["client_id"], group["id"])

        assert _token_count(test_tenant, client) == 2

    def test_remove_assignment_on_non_oidc_client_keeps_tokens(
        self, test_tenant, test_admin_user, test_user
    ):
        """A plain OAuth2 client is never group-gated, so removing an assignment
        does not restrict access and must not revoke tokens."""
        client = _client(test_tenant, test_admin_user, name="Plain With Group")
        client = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
        group = _group(test_tenant, name="Plain Assign")
        admin = _admin(test_tenant, test_admin_user)
        svc.assign_client_to_group(admin, client["client_id"], group["id"])
        _seed_tokens(test_tenant, client, test_user)

        svc.remove_client_group_assignment(admin, client["client_id"], group["id"])

        assert _token_count(test_tenant, client) == 2

    def test_narrowing_available_to_all_revokes_tokens(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _oidc_client(test_tenant, test_admin_user, available_to_all=True)
        admin = _admin(test_tenant, test_admin_user)
        _seed_tokens(test_tenant, client, test_user)
        assert _token_count(test_tenant, client) == 2

        svc.set_oidc_settings(admin, client["client_id"], available_to_all=False)

        assert _token_count(test_tenant, client) == 0

    def test_broadening_to_available_to_all_keeps_tokens(
        self, test_tenant, test_admin_user, test_user
    ):
        """Broadening access (group-gated -> available_to_all) revokes no one."""
        client = _oidc_client(test_tenant, test_admin_user, available_to_all=False)
        admin = _admin(test_tenant, test_admin_user)
        _seed_tokens(test_tenant, client, test_user)

        svc.set_oidc_settings(admin, client["client_id"], available_to_all=True)

        assert _token_count(test_tenant, client) == 2

    def test_disabling_oidc_while_narrowing_keeps_tokens(
        self, test_tenant, test_admin_user, test_user
    ):
        """Turning a client into a plain OAuth2 client removes group gating
        entirely (access broadens), so no revocation even as available_to_all
        flips to False in the same call."""
        client = _oidc_client(test_tenant, test_admin_user, available_to_all=True)
        admin = _admin(test_tenant, test_admin_user)
        _seed_tokens(test_tenant, client, test_user)

        svc.set_oidc_settings(
            admin, client["client_id"], oidc_enabled=False, available_to_all=False
        )

        assert _token_count(test_tenant, client) == 2


@pytest.fixture
def other_tenant():
    """A second, independent tenant with its own group (for isolation tests)."""
    t = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"oidc-mgmt-{uuid4().hex[:8]}", "n": "Other Tenant"},
    )
    tid = t["id"]
    admin = database.fetchone(
        tid,
        """
        INSERT INTO users (tenant_id, first_name, last_name, role)
        VALUES (:tid, 'Other', 'Admin', 'admin') RETURNING id
        """,
        {"tid": tid},
    )
    group = database.groups.create_group(
        tenant_id=tid, tenant_id_value=str(tid), name="Other Tenant Group"
    )
    yield {"id": tid, "admin_id": admin["id"], "group": group}
    database.execute(database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": tid})


class TestCrossTenantManagementIsolation:
    """An admin may only manage OIDC clients within their own tenant."""

    def _other_admin(self, other_tenant):
        return {
            "id": str(other_tenant["admin_id"]),
            "tenant_id": str(other_tenant["id"]),
            "role": "admin",
        }

    def test_cannot_toggle_other_tenant_client(self, test_tenant, test_admin_user, other_tenant):
        # Client belongs to tenant A; tenant B admin must not resolve it.
        a_client = _client(test_tenant, test_admin_user)
        with pytest.raises(NotFoundError):
            svc.set_oidc_settings(
                self._other_admin(other_tenant), a_client["client_id"], oidc_enabled=True
            )
        fresh = database.oauth2.get_client_by_client_id(test_tenant["id"], a_client["client_id"])
        assert fresh["oidc_enabled"] is False

    def test_cannot_read_other_tenant_urls(self, test_tenant, test_admin_user, other_tenant):
        a_client = _client(test_tenant, test_admin_user)
        with pytest.raises(NotFoundError):
            svc.get_client_discovery_info(
                self._other_admin(other_tenant), a_client["client_id"], "https://evil.example.com"
            )

    def test_cannot_list_other_tenant_client_groups(
        self, test_tenant, test_admin_user, other_tenant
    ):
        a_client = _client(test_tenant, test_admin_user)
        other_admin = self._other_admin(other_tenant)
        with pytest.raises(NotFoundError):
            svc.list_client_group_assignments(other_admin, a_client["client_id"])

    def test_cannot_assign_own_group_to_other_tenant_client(
        self, test_tenant, test_admin_user, other_tenant
    ):
        # Tenant B admin, tenant B group, tenant A client -> client not resolvable.
        a_client = _client(test_tenant, test_admin_user)
        with pytest.raises(NotFoundError):
            svc.assign_client_to_group(
                self._other_admin(other_tenant),
                a_client["client_id"],
                str(other_tenant["group"]["id"]),
            )

    def test_cannot_assign_foreign_group_to_own_client(
        self, test_tenant, test_admin_user, other_tenant
    ):
        # Tenant A admin + tenant A client, but a group_id owned by tenant B.
        a_client = _client(test_tenant, test_admin_user)
        with pytest.raises(NotFoundError):
            svc.assign_client_to_group(
                _admin(test_tenant, test_admin_user),
                a_client["client_id"],
                str(other_tenant["group"]["id"]),
            )

    def test_bulk_cannot_assign_foreign_group_and_fails_closed(
        self, test_tenant, test_admin_user, other_tenant
    ):
        # A batch mixing a valid tenant-A group with a foreign tenant-B group is
        # rejected wholesale (mirrors the single-assign validation); no partial
        # row is inserted, so no orphaned cross-tenant grant can be injected.
        a_client = _client(test_tenant, test_admin_user)
        a_group = _group(test_tenant)
        admin = _admin(test_tenant, test_admin_user)
        with pytest.raises(NotFoundError):
            svc.bulk_assign_client_to_groups(
                admin,
                a_client["client_id"],
                [str(a_group["id"]), str(other_tenant["group"]["id"])],
            )
        # Fail-closed: the valid group in the batch was not inserted either.
        assert svc.list_client_group_assignments(admin, a_client["client_id"]).total == 0
