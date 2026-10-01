#!/usr/bin/env python3
"""OIDC conformance test bed.

Provisions everything the OpenID Foundation conformance suite needs to test
WeftID as an OpenID Provider with static client registration:

  * a WeftID tenant (``oidc-conformance.weftid.localhost``),
  * a member user the suite's scripted browser logs in as,
  * three OIDC-enabled OAuth2 clients, all registered with the suite's
    callback URL and its ``post_logout_redirect`` URL (RP-initiated logout
    plan). The certification profiles exercise two clients with
    ``client_secret_basic`` and one with ``client_secret_post``; WeftID
    clients accept either method, so the three are identical apart from name.
  * a fourth client, identical but also registered with the suite's
    ``frontchannel_logout`` URL (session required), used only by the
    front-channel logout module (a config override). The other three must
    not have one: any module that ends a session would then load the logout
    iframe, and a suite module that does not expect the request fails.
  * a fifth client, registered with the suite's ``backchannel_logout`` URL
    (session required), used only by the back-channel logout module, for
    the same reason.
  * two ``private_key_jwt`` clients (sixth and seventh), registered with the
    public half of a fresh RSA key each, for the ``private_key_jwt`` variant
    of the general OIDC test plan. The private JWKS is returned so the suite
    can sign its client assertions.
  * dynamic client registration switched on (``open``, new clients available
    to all users) and a fresh initial access token, for the Dynamic OP and
    3rd Party-Init OP plans, which register their own clients. The suite
    sends the token with a module's first registration only, so the policy
    is open rather than token-gated; a presented token must still be valid.
    Clients that earlier runs registered, and earlier testbed tokens, are
    deleted first.

The host-side runner (``dev/oidc_conformance.py``) calls this inside the app
container with ``--json-output`` and renders the suite's plan config from the
result, so the client secrets are never written into the repository.

It also rotates the tenant's OIDC signing key on demand
(``--rotate-signing-key-flag``): ``oidcc-server-rotate-keys`` pauses until the
operator has rotated the OP's keys, and the runner's hook calls this then.

Usage:
    python ./dev/oidc_conformance_testbed.py --json-output
    python ./dev/oidc_conformance_testbed.py --rotate-signing-key-flag
    python ./dev/oidc_conformance_testbed.py --teardown-flag

Idempotent: safe to re-run. The clients are recreated on every run so the
plaintext secrets (only returned at creation) are always available.
"""

import hashlib
import json
import logging
import os
import secrets
import sys

import argh
import database
import database.oauth2
from dev.tenants import provision_tenant
from dev.users import add_user

log = logging.getLogger("oidc_conformance_testbed")

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

BASE_DOMAIN = "weftid.localhost"
SUBDOMAIN = "oidc-conformance"
TENANT_NAME = "OIDC Conformance"
USER_EMAIL = "conformance-user@oidc-conformance.test"
# Super admin that performs the signing-key rotation (the service requires one).
ADMIN_EMAIL = "conformance-admin@oidc-conformance.test"

# Suite defaults; see dev/oidc-conformance.sh. The alias is the fixed test
# instance name the suite uses for static-client plans; its callback URL is
# ``<suite base>/test/a/<alias>/callback``.
DEFAULT_SUITE_BASE_URL = "https://localhost.emobix.co.uk:8443"
DEFAULT_ALIAS = "weftid"

# (result key, client display name). Order matters: the runner maps these to
# the suite's ``client``, ``client2`` and ``client_secret_post`` sections.
CLIENTS = (
    ("client1", "Conformance client 1 (secret_basic)"),
    ("client2", "Conformance client 2 (secret_basic)"),
    ("client3", "Conformance client 3 (secret_post)"),
)

# The front-channel logout client (the ``client`` section of the
# oidcc-frontchannel-rp-initiated-logout override).
FRONTCHANNEL_CLIENT = ("client4", "Conformance client 4 (front-channel logout)")

# The back-channel logout client (the ``client`` section of the
# oidcc-backchannel-rp-initiated-logout override).
BACKCHANNEL_CLIENT = ("client5", "Conformance client 5 (back-channel logout)")


# The private_key_jwt clients (``client`` and ``client2`` of the
# private_key_jwt plan config).
PRIVATE_KEY_JWT_CLIENTS = (
    ("client6", "Conformance client 6 (private_key_jwt)"),
    ("client7", "Conformance client 7 (private_key_jwt)"),
)


# Name of the initial access token minted for the 3rd Party-Init OP plan.
IAT_NAME = "Conformance 3rd Party-Init OP"


def _tenant_id(subdomain: str) -> str:
    row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not row:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(row["id"])


def _recreate_client(
    tid: str,
    name: str,
    redirect_uri: str,
    post_logout_redirect_uri: str,
    created_by: str,
    frontchannel_logout_uri: str | None = None,
    backchannel_logout_uri: str | None = None,
) -> dict:
    """Delete any client with this name and create a fresh OIDC-enabled one."""
    for existing in database.oauth2.get_all_clients(tid, client_type="normal"):
        if existing["name"] == name:
            database.oauth2.delete_client(tid, existing["client_id"])
            log.info("Deleted stale client %s", existing["client_id"])

    client = database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=tid,
        name=name,
        redirect_uris=[redirect_uri],
        created_by=created_by,
        post_logout_redirect_uris=[post_logout_redirect_uri],
        frontchannel_logout_uri=frontchannel_logout_uri,
        frontchannel_logout_session_required=frontchannel_logout_uri is not None,
        backchannel_logout_uri=backchannel_logout_uri,
        backchannel_logout_session_required=backchannel_logout_uri is not None,
    )
    assert client is not None, f"client '{name}' not created"

    updated = database.oauth2.update_client_oidc_settings(
        tid,
        client["client_id"],
        oidc_enabled=True,
        available_to_all=True,
    )
    assert updated is not None and updated["oidc_enabled"], "oidc_enabled not set"
    log.info("Created OIDC-enabled client %s (%s)", client["client_id"], name)
    return {"client_id": client["client_id"], "client_secret": client["client_secret"]}


def _private_key_jwks() -> tuple[dict, dict]:
    """Generate an RS256 key; return (private JWKS, public JWKS)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    meta = {"kid": secrets.token_urlsafe(12), "alg": "RS256", "use": "sig"}
    private = {**RSAAlgorithm.to_jwk(key, as_dict=True), **meta}
    public = {**RSAAlgorithm.to_jwk(key.public_key(), as_dict=True), **meta}
    return {"keys": [private]}, {"keys": [public]}


def _recreate_private_key_jwt_client(
    tid: str, name: str, redirect_uri: str, post_logout_redirect_uri: str, created_by: str
) -> dict:
    """Recreate a client that authenticates with ``private_key_jwt``."""
    client = _recreate_client(tid, name, redirect_uri, post_logout_redirect_uri, created_by)
    private_jwks, public_jwks = _private_key_jwks()
    updated = database.oauth2.set_client_authentication(
        tid,
        client["client_id"],
        client_auth_method="private_key_jwt",
        jwks=public_jwks,
        jwks_uri=None,
        token_endpoint_auth_signing_alg=None,
        rotate_secret=True,
    )
    assert updated is not None, f"client '{name}' not switched to private_key_jwt"
    log.info("Switched %s to private_key_jwt", client["client_id"])
    return {"client_id": client["client_id"], "jwks": private_jwks}


def _enable_registration(tid: str, created_by: str) -> str:
    """Turn on open registration and mint an initial access token.

    Clients registered by earlier runs (the suite does not always delete what
    it registers) and earlier testbed tokens are removed first, so the tenant
    does not grow with every run. Returns the plaintext token.
    """
    database.execute(tid, "delete from oauth2_clients where dynamically_registered", {})
    database.execute(
        tid, "delete from oauth2_initial_access_tokens where name = :name", {"name": IAT_NAME}
    )
    database.oauth2.upsert_registration_settings(
        tid, tid, policy="open", default_access="all", updated_by=created_by
    )
    token = f"weft-id_iat_{secrets.token_urlsafe(32)}"
    database.oauth2.create_initial_access_token(
        tid,
        tid,
        name=IAT_NAME,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        created_by=created_by,
    )
    log.info("Enabled client registration (open) and minted '%s'", IAT_NAME)
    return token


def setup(suite_base_url: str, alias: str) -> dict:
    """Provision the testbed and return its config as a dict."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    provision_tenant(SUBDOMAIN, TENANT_NAME)
    tid = _tenant_id(SUBDOMAIN)

    add_user(
        SUBDOMAIN,
        USER_EMAIL,
        DEV_PASSWORD,
        role="member",
        first_name="Conformance",
        last_name="Tester",
    )
    from services.users import get_user_id_by_email

    uid = get_user_id_by_email(tid, USER_EMAIL)
    assert uid is not None, "user not created"

    issuer = f"https://{SUBDOMAIN}.{BASE_DOMAIN}"
    test_base = f"{suite_base_url.rstrip('/')}/test/a/{alias}"
    redirect_uri = f"{test_base}/callback"
    # The RP-initiated logout plan's static-client convention: the callback URL
    # with the part after the alias replaced by /post_logout_redirect.
    post_logout_redirect_uri = f"{test_base}/post_logout_redirect"

    clients = {
        key: _recreate_client(
            tid, name, redirect_uri, post_logout_redirect_uri, created_by=str(uid)
        )
        for key, name in CLIENTS
    }
    # Same convention for the front-channel logout plan: /frontchannel_logout.
    frontchannel_logout_uri = f"{test_base}/frontchannel_logout"
    key, name = FRONTCHANNEL_CLIENT
    clients[key] = _recreate_client(
        tid,
        name,
        redirect_uri,
        post_logout_redirect_uri,
        created_by=str(uid),
        frontchannel_logout_uri=frontchannel_logout_uri,
    )
    # And for the back-channel logout plan: /backchannel_logout.
    backchannel_logout_uri = f"{test_base}/backchannel_logout"
    key, name = BACKCHANNEL_CLIENT
    clients[key] = _recreate_client(
        tid,
        name,
        redirect_uri,
        post_logout_redirect_uri,
        created_by=str(uid),
        backchannel_logout_uri=backchannel_logout_uri,
    )

    for key, name in PRIVATE_KEY_JWT_CLIENTS:
        clients[key] = _recreate_private_key_jwt_client(
            tid, name, redirect_uri, post_logout_redirect_uri, created_by=str(uid)
        )

    initial_access_token = _enable_registration(tid, created_by=str(uid))

    return {
        "tenant_id": tid,
        "subdomain": SUBDOMAIN,
        "issuer": issuer,
        "user_email": USER_EMAIL,
        "password": DEV_PASSWORD,
        "redirect_uri": redirect_uri,
        "post_logout_redirect_uri": post_logout_redirect_uri,
        "frontchannel_logout_uri": frontchannel_logout_uri,
        "backchannel_logout_uri": backchannel_logout_uri,
        "alias": alias,
        "initial_access_token": initial_access_token,
        **clients,
    }


def rotate_signing_key() -> dict:
    """Rotate the testbed tenant's OIDC signing key through the service layer.

    A rotation is refused while the previous one's grace period runs (at
    least an hour), and conformance runs come closer together than that. The
    testbed ends any running grace period first, so every run rotates. Real
    tenants never take this shortcut.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    from services.oidc.keys import cleanup_previous_signing_key
    from services.oidc.keys import rotate_signing_key as rotate
    from services.types import RequestingUser
    from services.users import get_user_id_by_email
    from utils.request_context import system_context

    tid = _tenant_id(SUBDOMAIN)
    add_user(SUBDOMAIN, ADMIN_EMAIL, DEV_PASSWORD, role="super_admin")
    admin_id = get_user_id_by_email(tid, ADMIN_EMAIL)
    assert admin_id is not None, "admin not created"

    database.execute(
        tid,
        "update oidc_signing_keys set rotation_grace_period_ends_at = now() - interval '1 second'"
        " where rotation_grace_period_ends_at is not null",
        {},
    )
    with system_context():
        cleanup_previous_signing_key(tid, actor_user_id=str(admin_id))
        result = rotate(RequestingUser(id=str(admin_id), tenant_id=tid, role="super_admin"))
    log.info("Rotated signing key: %s -> %s", result.previous_kid, result.kid)
    return {"kid": result.kid, "previous_kid": result.previous_kid}


def teardown():
    """Delete the testbed tenant (cascades to users, clients, codes, tokens)."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    database.execute(
        database.UNSCOPED,
        "delete from tenants where subdomain = :subdomain",
        {"subdomain": SUBDOMAIN},
    )
    log.info("Deleted tenant '%s'", SUBDOMAIN)


def main(
    json_output: bool = False,
    teardown_flag: bool = False,
    rotate_signing_key_flag: bool = False,
    suite_base_url: str = DEFAULT_SUITE_BASE_URL,
    alias: str = DEFAULT_ALIAS,
):
    """Entry point.

    Args:
        json_output: print the config as JSON (for the host-side runner).
        teardown_flag: delete the testbed tenant and exit.
        rotate_signing_key_flag: rotate the tenant's OIDC signing key and exit.
        suite_base_url: the conformance suite's base URL (redirect URI host).
        alias: the suite test-instance alias used in the callback URL.
    """
    if teardown_flag:
        teardown()
        return
    if rotate_signing_key_flag:
        print(json.dumps(rotate_signing_key()))
        return
    config = setup(suite_base_url, alias)
    if json_output:
        print(json.dumps(config))
    else:
        for k, v in config.items():
            print(f"{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    # argh maps --json-output / --teardown-flag / --rotate-signing-key-flag /
    # --suite-base-url / --alias.
    argh.dispatch_command(main)
