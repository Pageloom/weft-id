#!/usr/bin/env python3
"""OIDC conformance test bed.

Provisions everything the OpenID Foundation conformance suite needs to test
WeftID as an OpenID Provider with static client registration:

  * a WeftID tenant (``oidc-conformance.weftid.localhost``),
  * a member user the suite's scripted browser logs in as,
  * three OIDC-enabled OAuth2 clients, all registered with the suite's
    callback URL. The certification profiles exercise two clients with
    ``client_secret_basic`` and one with ``client_secret_post``; WeftID
    clients accept either method, so the three are identical apart from name.

The host-side runner (``dev/oidc_conformance.py``) calls this inside the app
container with ``--json-output`` and renders the suite's plan config from the
result, so the client secrets are never written into the repository.

Usage:
    python ./dev/oidc_conformance_testbed.py --json-output
    python ./dev/oidc_conformance_testbed.py --teardown-flag

Idempotent: safe to re-run. The clients are recreated on every run so the
plaintext secrets (only returned at creation) are always available.
"""

import json
import logging
import os
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


def _tenant_id(subdomain: str) -> str:
    row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not row:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(row["id"])


def _recreate_client(tid: str, name: str, redirect_uri: str, created_by: str) -> dict:
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
    redirect_uri = f"{suite_base_url.rstrip('/')}/test/a/{alias}/callback"

    clients = {
        key: _recreate_client(tid, name, redirect_uri, created_by=str(uid)) for key, name in CLIENTS
    }

    return {
        "tenant_id": tid,
        "subdomain": SUBDOMAIN,
        "issuer": issuer,
        "user_email": USER_EMAIL,
        "password": DEV_PASSWORD,
        "redirect_uri": redirect_uri,
        "alias": alias,
        **clients,
    }


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
    suite_base_url: str = DEFAULT_SUITE_BASE_URL,
    alias: str = DEFAULT_ALIAS,
):
    """Entry point.

    Args:
        json_output: print the config as JSON (for the host-side runner).
        teardown_flag: delete the testbed tenant and exit.
        suite_base_url: the conformance suite's base URL (redirect URI host).
        alias: the suite test-instance alias used in the callback URL.
    """
    if teardown_flag:
        teardown()
        return
    config = setup(suite_base_url, alias)
    if json_output:
        print(json.dumps(config))
    else:
        for k, v in config.items():
            print(f"{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    # argh maps --json-output / --teardown-flag / --suite-base-url / --alias.
    argh.dispatch_command(main)
