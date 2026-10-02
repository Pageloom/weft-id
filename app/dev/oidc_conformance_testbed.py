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

For the RP plans (the suite plays the upstream OpenID Provider and WeftID's
upstream connector is the client under test) it also keeps one upstream OIDC
connection pointing at the suite's per-alias issuer
(``<suite>/test/a/<rp alias>/``): discovery-managed, JIT on, platform MFA
off, "sign out at the provider" on, with a fresh client secret every run.
The suite's static-client config takes the same client id, secret, the
connection's callback URL, WeftID's post-logout landing and the connection's
back-channel logout receiver.
``--expire-rp-discovery-flag`` ages that connection's discovery timestamp past
the TTL, so the next sign-in refetches discovery (each RP module publishes
its own keys and ``jwks_uri``).

It also rotates the tenant's OIDC signing key on demand
(``--rotate-signing-key-flag``): ``oidcc-server-rotate-keys`` pauses until the
operator has rotated the OP's keys, and the runner's hook calls this then.

Usage:
    python ./dev/oidc_conformance_testbed.py --json-output
    python ./dev/oidc_conformance_testbed.py --rotate-signing-key-flag
    python ./dev/oidc_conformance_testbed.py --expire-rp-discovery-flag
    python ./dev/oidc_conformance_testbed.py --test-rp-connection-flag
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
from typing import Any

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
# Alias of the RP plans' test instance: the suite's issuer for them is
# ``<suite base>/test/a/<rp alias>/``.
DEFAULT_RP_ALIAS = "weftid-rp"

# The upstream connection the RP plans sign in through, and the client id the
# suite's static-client config registers for it.
RP_CONNECTION_NAME = "Conformance suite OP"
RP_CLIENT_ID = "weftid-rp-conformance"

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


def _super_admin(tid: str):
    """The testbed's super admin as a RequestingUser (created on first use)."""
    from services.types import RequestingUser
    from services.users import get_user_id_by_email

    add_user(SUBDOMAIN, ADMIN_EMAIL, DEV_PASSWORD, role="super_admin")
    admin_id = get_user_id_by_email(tid, ADMIN_EMAIL)
    assert admin_id is not None, "admin not created"
    return RequestingUser(id=str(admin_id), tenant_id=tid, role="super_admin")


def _rp_connection_row(tid: str) -> dict | None:
    import database.oidc_upstream

    for row in database.oidc_upstream.list_connections(tid):
        if row["name"] == RP_CONNECTION_NAME:
            return row
    return None


def _ensure_rp_connection(tid: str, suite_base_url: str, rp_alias: str) -> dict:
    """Create or refresh the upstream connection to the suite's OP.

    Kept across runs (its id is in the callback URL, and JIT-provisioned
    users stay linked to it); the client secret is replaced every run so the
    plaintext is available for the suite config. Endpoints are left for
    sign-in to discover: the suite only serves the issuer while an RP module
    runs.
    """
    import services.oidc_upstream as oidc_service
    from schemas.oidc_upstream import OIDCConnectionCreate, OIDCConnectionUpdate
    from utils.request_context import system_context

    admin = _super_admin(tid)
    base_url = f"https://{SUBDOMAIN}.{BASE_DOMAIN}"
    issuer = f"{suite_base_url.rstrip('/')}/test/a/{rp_alias}/"
    secret = secrets.token_urlsafe(32)
    settings: dict[str, Any] = {
        "issuer": issuer,
        "discovery_url": f"{issuer}.well-known/openid-configuration",
        "client_id": RP_CLIENT_ID,
        "client_secret": secret,
        "scopes": "openid profile email",
        "jit_provisioning": True,
        "allow_email_linking": True,
        "require_platform_mfa": False,
        # The RP logout plans: sign-out continues to the suite's end_session.
        "sign_out_at_idp": True,
    }

    existing = _rp_connection_row(tid)
    with system_context():
        if existing is None:
            conn = oidc_service.create_connection(
                admin,
                OIDCConnectionCreate(
                    name=RP_CONNECTION_NAME, provider_type="generic", is_enabled=True, **settings
                ),
                base_url=base_url,
            )
            connection_id = conn.id
            log.info("Created upstream connection %s", connection_id)
        else:
            connection_id = str(existing["id"])
            oidc_service.update_connection(
                admin, connection_id, OIDCConnectionUpdate(**settings), base_url=base_url
            )
            if not existing.get("is_enabled"):
                oidc_service.set_connection_enabled(admin, connection_id, True, base_url=base_url)
            log.info("Refreshed upstream connection %s", connection_id)

    return {
        "connection_id": connection_id,
        "alias": rp_alias,
        "issuer": issuer,
        "client_id": RP_CLIENT_ID,
        "client_secret": secret,
        "redirect_uri": f"{base_url}/auth/oidc/{connection_id}/callback",
        "login_url": f"{base_url}/auth/oidc/{connection_id}/login",
        "post_logout_redirect_uri": f"{base_url}{oidc_service.POST_LOGOUT_PATH}",
        "backchannel_logout_uri": f"{base_url}/auth/oidc/{connection_id}/backchannel-logout",
    }


def expire_rp_discovery() -> dict:
    """Age the RP connection's discovery result past the TTL.

    Stands in for the hour passing between two RP modules: each module
    serves its own discovery document and keys, and a real RP would only
    refetch after its cache expired. A connection that was never discovered
    is left alone (sign-in discovers it anyway).
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    tid = _tenant_id(SUBDOMAIN)
    row = _rp_connection_row(tid)
    if row is None:
        raise RuntimeError("RP connection not provisioned; run the testbed first")
    database.execute(
        tid,
        "update oidc_idp_connections set discovery_fetched_at = now() - interval '1 day'"
        " where id = :id and discovery_fetched_at is not null",
        {"id": row["id"]},
    )
    return {"connection_id": str(row["id"])}


def test_rp_connection() -> dict:
    """Run the admin Test Connection action on the RP connection.

    Fetches the suite's discovery document and the JWKS it advertises, which
    is all the RP Config plan's discovery modules wait for (they end there;
    a full sign-in would call a module that has already finished). Failures
    are reported in the result, not raised: the module judges them.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    import services.oidc_upstream as oidc_service
    from services.exceptions import ServiceError
    from utils.request_context import system_context

    tid = _tenant_id(SUBDOMAIN)
    row = _rp_connection_row(tid)
    if row is None:
        raise RuntimeError("RP connection not provisioned; run the testbed first")
    with system_context():
        try:
            oidc_service.test_connection(
                _super_admin(tid), str(row["id"]), f"https://{SUBDOMAIN}.{BASE_DOMAIN}"
            )
        except ServiceError as exc:
            return {"connection_id": str(row["id"]), "result": "failed", "detail": exc.message}
    return {"connection_id": str(row["id"]), "result": "success"}


def setup(suite_base_url: str, alias: str, rp_alias: str = DEFAULT_RP_ALIAS) -> dict:
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
    rp = _ensure_rp_connection(tid, suite_base_url, rp_alias)

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
        "rp": rp,
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
    from utils.request_context import system_context

    tid = _tenant_id(SUBDOMAIN)
    admin = _super_admin(tid)

    database.execute(
        tid,
        "update oidc_signing_keys set rotation_grace_period_ends_at = now() - interval '1 second'"
        " where rotation_grace_period_ends_at is not null",
        {},
    )
    with system_context():
        cleanup_previous_signing_key(tid, actor_user_id=admin["id"])
        result = rotate(admin)
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
    expire_rp_discovery_flag: bool = False,
    test_rp_connection_flag: bool = False,
    suite_base_url: str = DEFAULT_SUITE_BASE_URL,
    alias: str = DEFAULT_ALIAS,
    rp_alias: str = DEFAULT_RP_ALIAS,
):
    """Entry point.

    Args:
        json_output: print the config as JSON (for the host-side runner).
        teardown_flag: delete the testbed tenant and exit.
        rotate_signing_key_flag: rotate the tenant's OIDC signing key and exit.
        expire_rp_discovery_flag: age the RP connection's discovery past the TTL and exit.
        test_rp_connection_flag: run Test Connection on the RP connection and exit.
        suite_base_url: the conformance suite's base URL (redirect URI host).
        alias: the suite test-instance alias used in the callback URL.
        rp_alias: the suite test-instance alias of the RP plans (issuer path).
    """
    if teardown_flag:
        teardown()
        return
    if rotate_signing_key_flag:
        print(json.dumps(rotate_signing_key()))
        return
    if expire_rp_discovery_flag:
        print(json.dumps(expire_rp_discovery()))
        return
    if test_rp_connection_flag:
        print(json.dumps(test_rp_connection()))
        return
    config = setup(suite_base_url, alias, rp_alias)
    if json_output:
        print(json.dumps(config))
    else:
        for k, v in config.items():
            print(f"{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    # argh maps --json-output / --teardown-flag / --rotate-signing-key-flag /
    # --expire-rp-discovery-flag / --test-rp-connection-flag / --suite-base-url /
    # --alias / --rp-alias.
    try:
        argh.dispatch_command(main)
    finally:
        # Close the pool before interpreter shutdown, or psycopg_pool's
        # finalizer tries to join its worker threads too late and prints a
        # PythonFinalizationError traceback on every call.
        database.close_pool()
