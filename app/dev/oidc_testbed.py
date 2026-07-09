#!/usr/bin/env python3
"""OIDC provider test bed.

Provisions everything the OIDC provider E2E test needs:

  * a WeftID tenant (``e2e-oidc.weftid.localhost``),
  * a member user (the relying party's end user),
  * a normal OAuth2 client with ``oidc_enabled`` and ``available_to_all`` set,
    registered with a redirect URI on the tenant host.

The E2E test drives a real browser through /oauth2/authorize (session-cookie
boundary), exchanges the code at /oauth2/token, and calls /userinfo (bearer
boundary).

Usage:
    python ./dev/oidc_testbed.py --json-output
    python ./dev/oidc_testbed.py --teardown-flag

Idempotent: safe to re-run. The OAuth2 client is recreated on every run so
the plaintext client secret (only returned at creation) is always available.
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

log = logging.getLogger("oidc_testbed")

DEV_PASSWORD = os.environ.get("DEV_PASSWORD", "devpass123")

BASE_DOMAIN = "weftid.localhost"
SUBDOMAIN = "e2e-oidc"
USER_EMAIL = "oidc-user@e2e-oidc.test"
CLIENT_NAME = "OIDC E2E Relying Party"
# A nonexistent path on the tenant host: the browser lands on a 404 page but
# the URL (carrying ?code=&state=) is still readable by the test.
CALLBACK_PATH = "/dev/oidc-rp-callback"


def _tenant_id(subdomain: str) -> str:
    row = database.fetchone(
        database.UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )
    if not row:
        raise RuntimeError(f"Tenant '{subdomain}' not found")
    return str(row["id"])


def setup() -> dict:
    """Provision the testbed and return its config as a dict."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    provision_tenant(SUBDOMAIN, "OIDC Provider E2E")
    tid = _tenant_id(SUBDOMAIN)

    add_user(
        SUBDOMAIN,
        USER_EMAIL,
        DEV_PASSWORD,
        role="member",
        first_name="Oidc",
        last_name="Tester",
    )
    from services.users import get_user_id_by_email

    uid = get_user_id_by_email(tid, USER_EMAIL)
    assert uid is not None, "user not created"

    base_url = f"https://{SUBDOMAIN}.{BASE_DOMAIN}"
    redirect_uri = f"{base_url}{CALLBACK_PATH}"

    # Recreate the client on every run: the plaintext secret is only returned
    # at creation, and the test needs it for the token exchange.
    for existing in database.oauth2.get_all_clients(tid, client_type="normal"):
        if existing["name"] == CLIENT_NAME:
            database.oauth2.delete_client(tid, existing["client_id"])
            log.info("Deleted stale client %s", existing["client_id"])

    client = database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=tid,
        name=CLIENT_NAME,
        redirect_uris=[redirect_uri],
        created_by=str(uid),
    )
    assert client is not None, "client not created"

    updated = database.oauth2.update_client_oidc_settings(
        tid,
        client["client_id"],
        oidc_enabled=True,
        available_to_all=True,
    )
    assert updated is not None and updated["oidc_enabled"], "oidc_enabled not set"
    log.info("Created OIDC-enabled client %s", client["client_id"])

    return {
        "tenant_id": tid,
        "subdomain": SUBDOMAIN,
        "base_url": base_url,
        "user_email": USER_EMAIL,
        "password": DEV_PASSWORD,
        "client_id": client["client_id"],
        "client_secret": client["client_secret"],
        "redirect_uri": redirect_uri,
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


def main(json_output: bool = False, teardown_flag: bool = False):
    """Entry point.

    Args:
        json_output: print the config as JSON (for test automation).
        teardown_flag: delete the testbed tenant and exit.
    """
    if teardown_flag:
        teardown()
        return
    config = setup()
    if json_output:
        print(json.dumps(config))
    else:
        for k, v in config.items():
            print(f"{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    # argh maps --json-output / --teardown-flag from the kwargs above.
    argh.dispatch_command(main)
