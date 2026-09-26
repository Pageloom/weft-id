"""Service tests for remembered consent (services.oidc.consent).

Covers the flow helpers the authorization endpoint uses (coverage test,
record-on-allow with create/widen/no-op semantics and their events), the
self-service list/revoke, the admin per-client list/revoke, authorization
boundaries, and the invalidation hooks in the owning services.
"""

from unittest.mock import patch
from uuid import uuid4

import database
import pytest
from services import oauth2 as oauth2_service
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.oidc import consent as svc
from services.users import state as users_state


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


def _client(test_tenant, test_admin_user, name="Consent Svc App"):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
    )


def _grant(test_tenant, client, user, scopes):
    return database.oauth2.upsert_consent_grant(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client["id"]),
        user_id=str(user["id"]),
        scopes=scopes,
    )


# ---------------------------------------------------------------------------
# Flow helpers
# ---------------------------------------------------------------------------


class TestConsentCovers:
    def test_no_grant_covers_nothing(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        tid = str(test_tenant["id"])
        assert svc.get_granted_scopes(tid, str(client["id"]), str(test_user["id"])) is None
        assert not svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), set())
        assert not svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), {"openid"})

    def test_bare_grant_covers_scopeless_request_only(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        _grant(test_tenant, client, test_user, [])
        tid = str(test_tenant["id"])
        assert svc.get_granted_scopes(tid, str(client["id"]), str(test_user["id"])) == set()
        assert svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), set())
        assert not svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), {"openid"})

    def test_superset_grant_covers(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        _grant(test_tenant, client, test_user, ["openid", "profile", "email"])
        tid = str(test_tenant["id"])
        assert svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), {"openid"})
        assert svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), {"openid", "email"})
        assert not svc.consent_covers(
            tid, str(client["id"]), str(test_user["id"]), {"openid", "groups"}
        )

    def test_grant_is_per_client_and_per_user(self, test_tenant, test_admin_user, test_user):
        a = _client(test_tenant, test_admin_user, "A")
        b = _client(test_tenant, test_admin_user, "B")
        _grant(test_tenant, a, test_user, ["openid"])
        tid = str(test_tenant["id"])
        assert not svc.consent_covers(tid, str(b["id"]), str(test_user["id"]), {"openid"})
        assert not svc.consent_covers(tid, str(a["id"]), str(test_admin_user["id"]), {"openid"})


class TestRecordConsent:
    def test_first_allow_creates_and_logs_granted(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        tid = str(test_tenant["id"])
        with patch("services.oidc.consent.log_event") as log:
            grant = svc.record_consent(tid, client, str(test_user["id"]), {"profile", "openid"})
        assert grant["scopes"] == ["openid", "profile"]
        assert log.call_count == 1
        kw = log.call_args.kwargs
        assert kw["event_type"] == "oauth2_consent_granted"
        assert kw["actor_user_id"] == str(test_user["id"])
        assert kw["artifact_type"] == "oauth2_consent_grant"
        assert kw["artifact_id"] == str(grant["id"])
        assert kw["metadata"]["client_id"] == client["client_id"]
        assert kw["metadata"]["scopes"] == ["openid", "profile"]
        assert kw["metadata"]["added_scopes"] == ["openid", "profile"]

    def test_wider_allow_widens_and_logs_added_scopes(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        tid = str(test_tenant["id"])
        _grant(test_tenant, client, test_user, ["openid"])
        with patch("services.oidc.consent.log_event") as log:
            grant = svc.record_consent(tid, client, str(test_user["id"]), {"openid", "email"})
        assert grant["scopes"] == ["email", "openid"]
        kw = log.call_args.kwargs
        assert kw["event_type"] == "oauth2_consent_widened"
        assert kw["metadata"]["added_scopes"] == ["email"]
        assert kw["metadata"]["scopes"] == ["email", "openid"]

    def test_covered_allow_writes_nothing_and_logs_nothing(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        tid = str(test_tenant["id"])
        existing = _grant(test_tenant, client, test_user, ["openid", "email"])
        with patch("services.oidc.consent.log_event") as log:
            grant = svc.record_consent(tid, client, str(test_user["id"]), {"openid"})
        assert grant["updated_at"] == existing["updated_at"]
        assert grant["scopes"] == ["email", "openid"]
        log.assert_not_called()

    def test_scopeless_allow_creates_a_bare_grant(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        tid = str(test_tenant["id"])
        with patch("services.oidc.consent.log_event"):
            grant = svc.record_consent(tid, client, str(test_user["id"]), set())
        assert grant["scopes"] == []
        assert svc.consent_covers(tid, str(client["id"]), str(test_user["id"]), set())


# ---------------------------------------------------------------------------
# Self-service
# ---------------------------------------------------------------------------


class TestSelfService:
    def test_list_my_grants_is_own_only_and_tracks_activity(
        self, test_tenant, test_admin_user, test_user
    ):
        a = _client(test_tenant, test_admin_user, "Beta")
        b = _client(test_tenant, test_admin_user, "Alpha")
        _grant(test_tenant, a, test_user, ["openid", "email"])
        _grant(test_tenant, b, test_user, ["openid"])
        _grant(test_tenant, a, test_admin_user, ["openid"])
        with patch("services.oidc.consent.track_activity") as track:
            grants = svc.list_my_grants(_member(test_tenant, test_user))
        track.assert_called_once_with(str(test_tenant["id"]), str(test_user["id"]))
        assert [g.client_name for g in grants] == ["Alpha", "Beta"]
        assert grants[1].client_id == a["client_id"]
        assert grants[1].scopes == ["email", "openid"]
        assert grants[1].client_is_active is True

    def test_list_my_grants_empty(self, test_tenant, test_user):
        assert svc.list_my_grants(_member(test_tenant, test_user)) == []

    def test_revoke_my_grant_deletes_and_logs(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        grant = _grant(test_tenant, client, test_user, ["openid"])
        with patch("services.oidc.consent.log_event") as log:
            svc.revoke_my_grant(_member(test_tenant, test_user), str(grant["id"]))
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"])) is None
        kw = log.call_args.kwargs
        assert kw["event_type"] == "oauth2_consent_revoked"
        assert kw["actor_user_id"] == str(test_user["id"])
        assert kw["artifact_id"] == str(grant["id"])
        assert kw["metadata"]["revoked_by"] == "user"
        assert kw["metadata"]["client_id"] == client["client_id"]
        assert kw["metadata"]["user_id"] == str(test_user["id"])
        assert kw["metadata"]["scopes"] == ["openid"]

    def test_revoke_my_grant_rejects_someone_elses(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        grant = _grant(test_tenant, client, test_admin_user, ["openid"])
        with pytest.raises(NotFoundError):
            svc.revoke_my_grant(_member(test_tenant, test_user), str(grant["id"]))
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"]))

    def test_revoke_my_grant_unknown_id(self, test_tenant, test_user):
        with pytest.raises(NotFoundError):
            svc.revoke_my_grant(_member(test_tenant, test_user), str(uuid4()))


# ---------------------------------------------------------------------------
# Admin per client
# ---------------------------------------------------------------------------


class TestAdmin:
    def test_list_client_grants(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        other = _client(test_tenant, test_admin_user, "Other")
        _grant(test_tenant, client, test_user, ["openid", "email"])
        _grant(test_tenant, other, test_user, ["openid"])
        with patch("services.oidc.consent.track_activity") as track:
            admin = _admin(test_tenant, test_admin_user)
            grants = svc.list_client_grants(admin, client["client_id"])
        track.assert_called_once()
        assert len(grants) == 1
        assert grants[0].user_id == str(test_user["id"])
        assert grants[0].user_email == test_user["email"]
        assert grants[0].user_name == f"{test_user['first_name']} {test_user['last_name']}"
        assert grants[0].scopes == ["email", "openid"]

    def test_list_client_grants_requires_admin(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        with pytest.raises(ForbiddenError):
            svc.list_client_grants(_member(test_tenant, test_user), client["client_id"])

    def test_list_client_grants_unknown_client(self, test_tenant, test_admin_user):
        with pytest.raises(NotFoundError):
            svc.list_client_grants(_admin(test_tenant, test_admin_user), "weft-id_client_nope")

    def test_list_client_grants_rejects_b2b(self, test_tenant, test_admin_user, b2b_oauth2_client):
        with pytest.raises(ValidationError):
            svc.list_client_grants(
                _admin(test_tenant, test_admin_user), b2b_oauth2_client["client_id"]
            )

    def test_revoke_client_grant_deletes_and_logs_admin(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        grant = _grant(test_tenant, client, test_user, ["openid"])
        with patch("services.oidc.consent.log_event") as log:
            svc.revoke_client_grant(
                _admin(test_tenant, test_admin_user), client["client_id"], str(grant["id"])
            )
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"])) is None
        kw = log.call_args.kwargs
        assert kw["event_type"] == "oauth2_consent_revoked"
        assert kw["actor_user_id"] == str(test_admin_user["id"])
        assert kw["metadata"]["revoked_by"] == "admin"
        assert kw["metadata"]["user_id"] == str(test_user["id"])

    def test_revoke_client_grant_requires_admin(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        grant = _grant(test_tenant, client, test_user, ["openid"])
        with pytest.raises(ForbiddenError):
            svc.revoke_client_grant(
                _member(test_tenant, test_user), client["client_id"], str(grant["id"])
            )

    def test_revoke_client_grant_must_belong_to_client(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        other = _client(test_tenant, test_admin_user, "Other")
        grant = _grant(test_tenant, other, test_user, ["openid"])
        with pytest.raises(NotFoundError):
            svc.revoke_client_grant(
                _admin(test_tenant, test_admin_user), client["client_id"], str(grant["id"])
            )
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"]))


# ---------------------------------------------------------------------------
# Invalidation hooks in the owning services
# ---------------------------------------------------------------------------


class TestInvalidation:
    def test_deactivating_a_client_forgets_its_grants(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        other = _client(test_tenant, test_admin_user, "Other")
        _grant(test_tenant, client, test_user, ["openid"])
        kept = _grant(test_tenant, other, test_user, ["openid"])
        with patch("services.oauth2.log_event") as log:
            oauth2_service.deactivate_client(
                str(test_tenant["id"]), client["client_id"], str(test_admin_user["id"])
            )
        assert (
            database.oauth2.list_consent_grants_for_client(test_tenant["id"], str(client["id"]))
            == []
        )
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(kept["id"]))
        assert log.call_args.kwargs["metadata"]["consents_revoked"] == 1

    def test_inactivating_a_user_forgets_their_grants(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        _grant(test_tenant, client, test_user, ["openid"])
        kept = _grant(test_tenant, client, test_admin_user, ["openid"])
        with patch("services.users.state.log_event"):
            users_state.inactivate_user(_admin(test_tenant, test_admin_user), str(test_user["id"]))
        assert (
            database.oauth2.list_consent_grants_for_user(test_tenant["id"], str(test_user["id"]))
            == []
        )
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(kept["id"]))
