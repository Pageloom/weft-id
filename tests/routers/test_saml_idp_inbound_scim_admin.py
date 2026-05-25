"""Tests for the inbound SCIM admin UI tab on a SAML Identity Provider.

Covers `/admin/settings/identity-providers/{idp_id}/scim` (the HTML tab)
which paints the credentials list and the "create / revoke" controls.
State-changing actions go through `WeftUtils.apiFetch` against the
`/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials`
endpoints; those are covered in `test_api_v1_inbound_scim_credentials.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from schemas.saml import IdPConfig
from schemas.scim_inbound import ScimInboundToken, ScimInboundTokenList

ROUTER_MODULE = "routers.saml.admin.inbound_scim"


@pytest.fixture
def idp_user():
    return {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "role": "super_admin",
        "email": "admin@test.com",
        "first_name": "Admin",
        "last_name": "User",
        "tz": "UTC",
        "locale": "en_US",
    }


@pytest.fixture
def idp_admin_session(client, idp_user, override_auth):
    override_auth(idp_user, level="super_admin")
    yield client


@pytest.fixture
def idp_host(idp_user):
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup(idp_user):
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": idp_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def sample_idp(idp_user):
    return IdPConfig(
        id=str(uuid4()),
        name="Acme Okta",
        provider_type="generic",
        entity_id=None,
        sso_url=None,
        slo_url=None,
        certificate_pem=None,
        metadata_url=None,
        metadata_xml=None,
        metadata_last_fetched_at=None,
        metadata_fetch_error=None,
        sp_entity_id="urn:test:weftid",
        sp_acs_url="https://test.example/acs",
        attribute_mapping={},
        is_enabled=True,
        is_default=False,
        require_platform_mfa=False,
        jit_provisioning=False,
        trust_established=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _empty_tokens():
    return ScimInboundTokenList(items=[], total=0)


def _one_token(idp_id):
    return ScimInboundTokenList(
        items=[
            ScimInboundToken(
                id=str(uuid4()),
                idp_id=idp_id,
                name="Okta production",
                created_by_user_id=str(uuid4()),
                created_at=datetime.now(UTC),
                revoked_at=None,
                last_used_at=None,
            )
        ],
        total=1,
    )


def test_inbound_scim_tab_renders(idp_admin_session, idp_host, sample_idp, mocker):
    """Tab renders the inbound SCIM template with the right context keys."""
    mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>inbound scim</html>")

    with (
        patch(
            "services.saml.get_identity_provider",
            return_value=sample_idp,
        ),
        patch(
            "services.scim.inbound_credentials.list_tokens",
            return_value=_one_token(sample_idp.id),
        ),
    ):
        response = idp_admin_session.get(
            f"/admin/settings/identity-providers/{sample_idp.id}/scim",
            headers={"Host": idp_host},
        )

    assert response.status_code == 200
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "saml_idp_tab_scim_inbound.html"
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["active_tab"] == "scim"
    assert "idp" in ctx_kwargs
    assert "tokens" in ctx_kwargs
    assert "scim_base_url" in ctx_kwargs
    # The SCIM base URL must include the IdP id so iteration 2 can route
    # inbound requests to the right tenant connection.
    assert sample_idp.id in ctx_kwargs["scim_base_url"]
    assert ctx_kwargs["scim_base_url"].endswith("/")


def test_inbound_scim_tab_redirects_non_super_admin(client, idp_user, override_auth, idp_host):
    """Admin (non-super) is rejected by `require_super_admin` router dep."""
    admin_user = {**idp_user, "role": "admin"}
    override_auth(admin_user, level="admin")
    response = client.get(
        f"/admin/settings/identity-providers/{uuid4()}/scim",
        headers={"Host": idp_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] in ("/dashboard", "/login")


def test_inbound_scim_tab_redirects_when_idp_missing(idp_admin_session, idp_host):
    """Unknown idp id redirects to the IdP list with an error query string."""
    from services.exceptions import NotFoundError

    idp_id = str(uuid4())
    with patch(
        "services.saml.get_identity_provider",
        side_effect=NotFoundError(message="missing", code="idp_not_found"),
    ):
        response = idp_admin_session.get(
            f"/admin/settings/identity-providers/{idp_id}/scim",
            headers={"Host": idp_host},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "/admin/settings/identity-providers" in response.headers["location"]
    assert "error" in response.headers["location"]


def test_inbound_scim_tab_uses_x_forwarded_host_for_base_url(
    idp_admin_session, idp_host, sample_idp, mocker
):
    """The SCIM base URL must reflect the outward-facing host (behind nginx).

    The receiver in Okta / Entra must hit the public hostname, not the
    pod-internal one. The router reads `x-forwarded-host` so the value
    surfaced to admins is the real tenant URL.
    """
    mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>x</html>")

    with (
        patch(
            "services.saml.get_identity_provider",
            return_value=sample_idp,
        ),
        patch(
            "services.scim.inbound_credentials.list_tokens",
            return_value=_empty_tokens(),
        ),
    ):
        response = idp_admin_session.get(
            f"/admin/settings/identity-providers/{sample_idp.id}/scim",
            headers={
                "Host": idp_host,
                "x-forwarded-host": "acme.weftid.com",
            },
        )

    assert response.status_code == 200
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["scim_base_url"].startswith("https://acme.weftid.com/")
