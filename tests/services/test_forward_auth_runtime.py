"""Unit tests for the forward-auth runtime decision + audit logic.

These cover the pure helpers in services.forward_auth that the iteration-5 router
relies on: path matching, header building (X-Forwarded-* from identity only),
access decision + audit verbosity, identity assembly, and the domain/app
resolution + open-redirect-adjacent helpers. DB and event-log calls are mocked;
the route-level tests exercise the real DB.
"""

from unittest.mock import patch

import pytest
import services.forward_auth as fa

# ---------------------------------------------------------------------------
# Public-path matching
# ---------------------------------------------------------------------------


class TestPublicPathMatching:
    def test_exact_match(self):
        app = {"public_paths": ["/health", "/favicon.ico"]}
        assert fa.is_public_path(app, "/health") is True
        assert fa.is_public_path(app, "/favicon.ico") is True

    def test_no_match(self):
        app = {"public_paths": ["/health"]}
        assert fa.is_public_path(app, "/admin") is False

    def test_prefix_wildcard(self):
        app = {"public_paths": ["/static/*"]}
        assert fa.is_public_path(app, "/static/app.css") is True
        assert fa.is_public_path(app, "/static/") is True
        # '/static/*' -> prefix '/static/'; '/staticx' must NOT match (safe).
        assert fa.is_public_path(app, "/staticx") is False
        assert fa.is_public_path(app, "/other") is False

    def test_empty_or_missing_public_paths(self):
        assert fa.is_public_path({"public_paths": []}, "/x") is False
        assert fa.is_public_path({}, "/x") is False
        assert fa.is_public_path({"public_paths": None}, "/x") is False

    def test_non_list_public_paths_denies(self):
        assert fa.is_public_path({"public_paths": "/x"}, "/x") is False

    def test_dot_dot_traversal_never_public(self):
        # A backend that normalizes '..' could turn a public-prefix-matching
        # request into a protected one (/static/../admin -> /admin). Such a path
        # must NOT be treated as public, even though it prefix-matches.
        app = {"public_paths": ["/static/*", "/public/*"]}
        assert fa.is_public_path(app, "/static/../admin") is False
        assert fa.is_public_path(app, "/public/../../etc/passwd") is False
        assert fa.is_public_path(app, "/static/..") is False
        # A literal '..' in a filename segment (not a traversal token) still
        # prefix-matches and stays public -- only a bare '..' segment is blocked.
        assert fa.is_public_path(app, "/static/a..b.css") is True


# ---------------------------------------------------------------------------
# Forwarded-header construction (identity-only, never reflected)
# ---------------------------------------------------------------------------


class TestBuildForwardedHeaders:
    def _identity(self):
        return {
            "user_id": "u-1",
            "email": "a@b.com",
            "display_name": "Alice B",
            "groups": ["eng", "all"],
        }

    def test_only_enabled_headers_emitted(self):
        app = {"header_config": {"user": True, "email": False, "groups": True}}
        headers = fa.build_forwarded_headers(app, self._identity())
        assert headers == {
            "X-Forwarded-User": "u-1",
            "X-Forwarded-Groups": "eng,all",
        }
        assert "X-Forwarded-Email" not in headers

    def test_all_headers(self):
        app = {
            "header_config": {
                "user": True,
                "email": True,
                "groups": True,
                "display_name": True,
            }
        }
        headers = fa.build_forwarded_headers(app, self._identity())
        assert headers["X-Forwarded-User"] == "u-1"
        assert headers["X-Forwarded-Email"] == "a@b.com"
        assert headers["X-Forwarded-Display-Name"] == "Alice B"
        assert headers["X-Forwarded-Groups"] == "eng,all"

    def test_no_config_emits_nothing(self):
        assert fa.build_forwarded_headers({"header_config": {}}, self._identity()) == {}
        assert fa.build_forwarded_headers({}, self._identity()) == {}

    def test_crlf_stripped_to_prevent_response_splitting(self):
        identity = {
            "user_id": "u\r\n-evil",
            "email": "e\n@b.com",
            "display_name": "n\rx",
            "groups": ["g\n1", "g2"],
        }
        app = {
            "header_config": {
                "user": True,
                "email": True,
                "display_name": True,
                "groups": True,
            }
        }
        headers = fa.build_forwarded_headers(app, identity)
        for value in headers.values():
            assert "\r" not in value
            assert "\n" not in value
        assert headers["X-Forwarded-User"] == "u-evil"
        assert headers["X-Forwarded-Groups"] == "g1,g2"


# ---------------------------------------------------------------------------
# Access decision + audit verbosity
# ---------------------------------------------------------------------------


class TestAuthorizeAppAccess:
    def test_allow_does_not_log(self):
        with (
            patch.object(
                fa.database.sp_group_assignments, "user_can_access_app", return_value=True
            ),
            patch.object(fa, "log_event") as log,
        ):
            allowed = fa.authorize_app_access(
                tenant_id="t1", user_id="u1", proxy_app_id="a1", domain="acme.com"
            )
        assert allowed is True
        log.assert_not_called()  # first-allow is logged at /callback, not here

    def test_deny_logs_proxy_access_denied(self):
        with (
            patch.object(
                fa.database.sp_group_assignments, "user_can_access_app", return_value=False
            ),
            patch.object(fa, "log_event") as log,
        ):
            allowed = fa.authorize_app_access(
                tenant_id="t1",
                user_id="u1",
                proxy_app_id="a1",
                domain="acme.com",
                app_name="Grafana",
            )
        assert allowed is False
        log.assert_called_once()
        kwargs = log.call_args.kwargs
        assert kwargs["event_type"] == "proxy_access_denied"
        assert kwargs["artifact_id"] == "a1"
        assert kwargs["metadata"]["domain"] == "acme.com"
        assert kwargs["metadata"]["proxy_app_name"] == "Grafana"

    def test_log_access_granted_emits_granted(self):
        with patch.object(fa, "log_event") as log:
            fa.log_access_granted(
                tenant_id="t1",
                user_id="u1",
                proxy_app_id="a1",
                domain="acme.com",
                app_name="G",
            )
        assert log.call_args.kwargs["event_type"] == "proxy_access_granted"

    def test_log_session_expired_uses_system_actor(self):
        with patch.object(fa, "log_event") as log:
            fa.log_session_expired(tenant_id="t1", proxy_app_id="a1", domain="acme.com")
        kwargs = log.call_args.kwargs
        assert kwargs["event_type"] == "proxy_session_expired"
        assert kwargs["actor_user_id"] == "00000000-0000-0000-0000-000000000000"


class TestRecheckCookieAccess:
    """The /check re-check: re-resolve per-app grant for a valid cookie."""

    _UID = "00000000-0000-0000-0000-0000000000c1"

    def test_allow_does_not_log(self):
        with (
            patch.object(
                fa.database.sp_group_assignments, "user_can_access_proxy_app", return_value=True
            ),
            patch.object(fa, "log_event") as log,
        ):
            allowed = fa.recheck_cookie_access(
                tenant_id="t1", user_id=self._UID, proxy_app_id="a1", domain="acme.com"
            )
        assert allowed is True
        log.assert_not_called()

    def test_deny_logs_proxy_access_denied(self):
        with (
            patch.object(
                fa.database.sp_group_assignments, "user_can_access_proxy_app", return_value=False
            ),
            patch.object(fa, "log_event") as log,
        ):
            allowed = fa.recheck_cookie_access(
                tenant_id="t1",
                user_id=self._UID,
                proxy_app_id="a1",
                domain="acme.com",
                app_name="Grafana",
            )
        assert allowed is False
        log.assert_called_once()
        kwargs = log.call_args.kwargs
        assert kwargs["event_type"] == "proxy_access_denied"
        assert kwargs["actor_user_id"] == self._UID
        assert kwargs["artifact_id"] == "a1"
        assert kwargs["metadata"]["domain"] == "acme.com"
        assert kwargs["metadata"]["proxy_app_name"] == "Grafana"

    def test_uses_proxy_app_grant_resolver(self):
        # Routes to user_can_access_proxy_app (proxy-app kind), not the SP one.
        with (
            patch.object(
                fa.database.sp_group_assignments, "user_can_access_proxy_app", return_value=True
            ) as resolver,
            patch.object(fa, "log_event"),
        ):
            fa.recheck_cookie_access(
                tenant_id="t1", user_id=self._UID, proxy_app_id="a1", domain="acme.com"
            )
        resolver.assert_called_once_with("t1", self._UID, "a1")

    def test_non_uuid_subject_fails_closed(self):
        # A non-UUID cookie subject (only reachable via a malformed cookie, which
        # the HMAC rules out) denies without touching the DB or erroring.
        with (
            patch.object(fa.database.sp_group_assignments, "user_can_access_proxy_app") as resolver,
            patch.object(fa, "log_event") as log,
        ):
            allowed = fa.recheck_cookie_access(
                tenant_id="t1", user_id="not-a-uuid", proxy_app_id="a1", domain="acme.com"
            )
        assert allowed is False
        resolver.assert_not_called()
        log.assert_not_called()


# ---------------------------------------------------------------------------
# Identity assembly
# ---------------------------------------------------------------------------


class TestBuildForwardAuthIdentity:
    def test_active_user(self):
        user = {"first_name": "Alice", "last_name": "B", "is_inactivated": False}
        with (
            patch.object(fa.database.users, "get_user_by_id", return_value=user),
            patch.object(
                fa.database.user_emails, "get_primary_email", return_value={"email": "a@b.com"}
            ),
            patch.object(fa.database.groups, "get_effective_group_names", return_value=["eng"]),
        ):
            identity = fa.build_forward_auth_identity("t1", "u1")
        assert identity == {
            "user_id": "u1",
            "email": "a@b.com",
            "display_name": "Alice B",
            "groups": ["eng"],
        }

    def test_display_name_falls_back_to_email(self):
        user = {"first_name": "", "last_name": "", "is_inactivated": False}
        with (
            patch.object(fa.database.users, "get_user_by_id", return_value=user),
            patch.object(
                fa.database.user_emails, "get_primary_email", return_value={"email": "a@b.com"}
            ),
            patch.object(fa.database.groups, "get_effective_group_names", return_value=[]),
        ):
            identity = fa.build_forward_auth_identity("t1", "u1")
        assert identity["display_name"] == "a@b.com"

    @pytest.mark.parametrize(
        "user",
        [
            None,
            {"is_inactivated": True},
            {"is_anonymized": True},
        ],
    )
    def test_missing_or_inactive_user_fails_closed(self, user):
        with patch.object(fa.database.users, "get_user_by_id", return_value=user):
            assert fa.build_forward_auth_identity("t1", "u1") is None


# ---------------------------------------------------------------------------
# Domain / app resolution helpers
# ---------------------------------------------------------------------------


class TestDomainResolution:
    def _verified(self):
        return {
            "id": "d1",
            "verification_status": "verified",
            "enabled": True,
            "portal_host": "auth.acme.com",
        }

    def test_resolve_by_host_requires_verified_domain(self):
        with patch.object(
            fa.database.protected_domains,
            "get_protected_domain_by_domain",
            return_value={"id": "d1", "verification_status": "pending", "enabled": True},
        ):
            assert (
                fa.resolve_proxy_app_by_host(
                    tenant_id="t1", domain="acme.com", external_host="g.acme.com"
                )
                is None
            )

    def test_resolve_by_host_returns_app(self):
        app = {"id": "a1"}
        with (
            patch.object(
                fa.database.protected_domains,
                "get_protected_domain_by_domain",
                return_value=self._verified(),
            ),
            patch.object(
                fa.database.proxy_apps,
                "get_enabled_proxy_app_for_domain_and_host",
                return_value=app,
            ) as q,
        ):
            result = fa.resolve_proxy_app_by_host(
                tenant_id="t1", domain="acme.com", external_host="g.acme.com"
            )
        assert result is app
        q.assert_called_once_with("t1", "d1", "g.acme.com")

    def test_sole_enabled_app_single(self):
        with (
            patch.object(
                fa.database.protected_domains,
                "get_protected_domain_by_domain",
                return_value=self._verified(),
            ),
            patch.object(
                fa.database.proxy_apps,
                "list_proxy_apps_for_domain",
                return_value=[{"id": "a1", "enabled": True}],
            ),
        ):
            result = fa.resolve_sole_enabled_app(tenant_id="t1", domain="acme.com")
        assert result["id"] == "a1"

    def test_sole_enabled_app_ambiguous_fails_closed(self):
        with (
            patch.object(
                fa.database.protected_domains,
                "get_protected_domain_by_domain",
                return_value=self._verified(),
            ),
            patch.object(
                fa.database.proxy_apps,
                "list_proxy_apps_for_domain",
                return_value=[{"id": "a1", "enabled": True}, {"id": "a2", "enabled": True}],
            ),
        ):
            assert fa.resolve_sole_enabled_app(tenant_id="t1", domain="acme.com") is None

    def test_get_tenant_verified_domain_portal_host_must_match(self):
        with patch.object(
            fa.database.protected_domains,
            "get_protected_domain_by_domain",
            return_value=self._verified(),
        ):
            # Matching portal host -> returns row.
            assert (
                fa.get_tenant_verified_domain(
                    tenant_id="t1", domain="acme.com", portal_host="auth.acme.com"
                )
                is not None
            )
            # Mismatched portal host -> fail closed.
            assert (
                fa.get_tenant_verified_domain(
                    tenant_id="t1", domain="acme.com", portal_host="evil.acme.com"
                )
                is None
            )

    def test_resolve_app_for_rd_absolute_url_matches_host(self):
        app = {"id": "a1"}
        with patch.object(
            fa.database.proxy_apps,
            "get_enabled_proxy_app_for_domain_and_host",
            return_value=app,
        ) as q:
            result = fa.resolve_app_for_rd(
                tenant_id="t1", protected_domain_id="d1", rd="https://g.acme.com/dash"
            )
        assert result is app
        q.assert_called_once_with("t1", "d1", "g.acme.com")

    def test_resolve_app_for_rd_relative_falls_back_to_sole_app(self):
        with patch.object(
            fa.database.proxy_apps,
            "list_proxy_apps_for_domain",
            return_value=[{"id": "a1", "enabled": True}],
        ):
            result = fa.resolve_app_for_rd(
                tenant_id="t1", protected_domain_id="d1", rd="/dashboard"
            )
        assert result["id"] == "a1"

    def test_get_app_for_callback_requires_enabled(self):
        with patch.object(
            fa.database.proxy_apps, "get_proxy_app", return_value={"id": "a1", "enabled": False}
        ):
            assert fa.get_app_for_callback(tenant_id="t1", proxy_app_id="a1") is None
        with patch.object(
            fa.database.proxy_apps, "get_proxy_app", return_value={"id": "a1", "enabled": True}
        ):
            assert fa.get_app_for_callback(tenant_id="t1", proxy_app_id="a1") == {
                "id": "a1",
                "enabled": True,
            }


class TestCanonicalTenantHost:
    def test_builds_host(self):
        with (
            patch.object(fa.settings, "BASE_DOMAIN", "weft.id"),
            patch.object(
                fa.database.tenants, "get_tenant_by_id", return_value={"subdomain": "acme"}
            ),
        ):
            assert fa.get_canonical_tenant_host("t1") == "acme.weft.id"

    def test_no_base_domain_fails_closed(self):
        with patch.object(fa.settings, "BASE_DOMAIN", ""):
            assert fa.get_canonical_tenant_host("t1") is None

    def test_unknown_tenant_fails_closed(self):
        with (
            patch.object(fa.settings, "BASE_DOMAIN", "weft.id"),
            patch.object(fa.database.tenants, "get_tenant_by_id", return_value=None),
        ):
            assert fa.get_canonical_tenant_host("t1") is None


def test_resolve_proxy_app_by_host_empty_host():
    # A verified domain with an empty original host -> None (no app match).
    with patch.object(
        fa.database.protected_domains,
        "get_protected_domain_by_domain",
        return_value={
            "id": "d1",
            "verification_status": "verified",
            "enabled": True,
            "portal_host": "auth.acme.com",
        },
    ):
        assert (
            fa.resolve_proxy_app_by_host(tenant_id="t1", domain="acme.com", external_host="")
            is None
        )
