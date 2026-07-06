"""Unit tests for OIDC userinfo assembly (services/oidc/userinfo.py).

The userinfo service reuses the shared claim assembler and only adds `sub`.
These cover sub-always-present, scope gating, the audit event, and read
activity tracking.
"""

from unittest.mock import patch

from services.oidc import userinfo as userinfo_service


class TestGetUserInfo:
    def test_sub_always_present(self, test_tenant, test_user):
        info = userinfo_service.get_userinfo(
            tenant_id=str(test_tenant["id"]),
            user_id=str(test_user["id"]),
            client_uuid="00000000-0000-0000-0000-0000000000aa",
            client_id="weft-id_client_x",
            scope="openid",
        )
        assert info["sub"] == str(test_user["id"])
        # No profile/email scope => only sub.
        assert set(info.keys()) == {"sub"}

    def test_scope_gates_email_claims(self, test_tenant, test_user):
        info = userinfo_service.get_userinfo(
            tenant_id=str(test_tenant["id"]),
            user_id=str(test_user["id"]),
            client_uuid="00000000-0000-0000-0000-0000000000aa",
            client_id="cid",
            scope="openid email",
        )
        assert info["sub"] == str(test_user["id"])
        assert info["email"] == test_user["email"]
        assert "name" not in info

    def test_null_scope_still_returns_sub(self, test_tenant, test_user):
        info = userinfo_service.get_userinfo(
            tenant_id=str(test_tenant["id"]),
            user_id=str(test_user["id"]),
            client_uuid="00000000-0000-0000-0000-0000000000aa",
            client_id="cid",
            scope=None,
        )
        assert info == {"sub": str(test_user["id"])}

    def test_emits_event_and_tracks_activity(self, test_tenant, test_user):
        with (
            patch("services.oidc.userinfo.log_event") as mock_log,
            patch("services.oidc.userinfo.track_activity") as mock_track,
        ):
            userinfo_service.get_userinfo(
                tenant_id=str(test_tenant["id"]),
                user_id=str(test_user["id"]),
                client_uuid="00000000-0000-0000-0000-0000000000aa",
                client_id="cid",
                scope="openid email profile",
            )
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_user["id"]))
        assert mock_log.call_count == 1
        kwargs = mock_log.call_args.kwargs
        assert kwargs["event_type"] == "oidc_userinfo_accessed"
        assert kwargs["artifact_type"] == "oauth2_client"
        assert kwargs["artifact_id"] == "00000000-0000-0000-0000-0000000000aa"
        assert kwargs["metadata"]["scopes"] == ["email", "openid", "profile"]
