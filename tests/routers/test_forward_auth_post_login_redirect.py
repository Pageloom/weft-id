"""Unit tests for the forward-auth post-login redirect branch.

After a user logs in to satisfy a forward-auth /authorize step, login
completion must bounce them back to the stashed authorize URL via
get_post_auth_redirect. Only a safe rooted-relative /forward-auth/authorize
path is honored (open-redirect guard).
"""

from routers.saml_idp._helpers import get_post_auth_redirect


def test_pending_forward_auth_authorize_honored_and_consumed():
    target = "/forward-auth/authorize?domain=acme.com&portal_host=auth.acme.com&rd=%2Fx"
    session = {"pending_forward_auth_authorize": target}
    assert get_post_auth_redirect(session) == target
    # Consumed (popped) so it is not replayed on a later login.
    assert "pending_forward_auth_authorize" not in session


def test_pending_sso_takes_priority():
    session = {
        "pending_sso_sp_entity_id": "sp1",
        "pending_forward_auth_authorize": "/forward-auth/authorize?domain=a",
    }
    assert get_post_auth_redirect(session) == "/saml/idp/consent"


def test_open_redirect_value_ignored():
    for bad in (
        "https://evil.example/forward-auth/authorize",
        "//evil.example",
        "/dashboard",  # not a forward-auth authorize path
        "/forward-auth/authorize\nLocation: https://evil",  # CRLF injection
        "/forward-auth/authorize\rhttps://evil",
    ):
        session = {"pending_forward_auth_authorize": bad}
        assert get_post_auth_redirect(session) == "/dashboard"


def test_default_when_nothing_pending():
    assert get_post_auth_redirect({}) == "/dashboard"
